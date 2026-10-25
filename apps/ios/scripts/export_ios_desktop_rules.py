#!/usr/bin/env python3
"""Export policy-only rules using cached desktop providers; never export nodes.

Import the JSON in the iOS Rules page. YAML providers are expanded without
fetching subscriptions. MRS conversion delegates to the existing desktop core.
Rules that cannot be represented exactly are rejected, never approximated.
"""
import argparse
import datetime
import glob
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import yaml

PLACEHOLDER = '__IOS_PROXY__'
SUPPORTED = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6', 'GEOIP', 'NETWORK', 'MATCH'}
SKIPPED = {'PROCESS-NAME', 'PROCESS-PATH', 'UID', 'IN-TYPE', 'IN-PORT'}
MAX_RULES = 50_000
MAX_PROVIDER_BYTES = 8 * 1024 * 1024


def load_proxies(socket_path):
    connection = http.client.HTTPConnection('localhost', timeout=8)
    connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.sock.settimeout(8)
    connection.sock.connect(socket_path)
    try:
        connection.request('GET', '/proxies')
        response = connection.getresponse()
        if response.status != 200:
            raise RuntimeError('Desktop controller returned HTTP ' + str(response.status))
        return json.loads(response.read())['proxies']
    finally:
        connection.close()


def leaf(proxies, name, seen=()):
    if name in seen:
        raise ValueError('Cycle in desktop selector: ' + name)
    proxy = proxies.get(name)
    if proxy is None and name not in {'DIRECT', 'REJECT', 'REJECT-DROP'}:
        raise ValueError('Missing desktop policy: ' + name)
    return leaf(proxies, proxy['now'], (*seen, name)) if proxy and proxy.get('now') else name



def validate_portable_rule(rule):
    parts = rule.split(',')
    kind = parts[0]
    expected = 2 if kind == 'MATCH' else 3
    if kind not in SUPPORTED or len(parts) not in {expected, expected + 1} or any(not v or v != v.strip() or '\n' in v or '\r' in v for v in parts):
        raise ValueError('Malformed portable rule: ' + kind)
    if parts[expected - 1] not in {'DIRECT', 'REJECT', PLACEHOLDER}:
        raise ValueError('Invalid portable policy: ' + kind)
    if len(parts) > expected and parts[-1] != 'no-resolve':
        raise ValueError('Unsupported portable rule flag: ' + kind)
    if kind == 'NETWORK' and (len(parts) != 3 or parts[1].lower() not in {'udp', 'tcp'}):
        raise ValueError('NETWORK requires tcp/udp and no additional flags')
    if kind.startswith('DOMAIN') and not re.fullmatch(r'[A-Za-z0-9_.-]+', parts[1]):
        raise ValueError('Invalid portable domain rule')
    if kind in {'IP-CIDR', 'IP-CIDR6'}:
        network = ipaddress.ip_network(parts[1], strict=False)
        if network.version != (6 if kind == 'IP-CIDR6' else 4):
            raise ValueError('CIDR address family does not match the mobile rule')
    if kind == 'GEOIP' and not re.fullmatch(r'[A-Za-z]{2}', parts[1]):
        raise ValueError('Unsupported portable GeoIP selector')


def provider_rules(config, name, target, flags, base_dir, mihomo_binary):
    provider = config.get('rule-providers', {}).get(name)
    if not isinstance(provider, dict):
        raise ValueError('Missing rule provider: ' + name)
    behavior = provider.get('behavior')
    if behavior not in {'domain', 'ipcidr', 'classical'}:
        raise ValueError('Unsupported provider behavior: ' + str(behavior))
    relative = provider.get('path')
    if not isinstance(relative, str) or not relative:
        raise ValueError('Provider must have a local cached path: ' + name)
    source = Path(relative)
    if not source.is_absolute():
        source = base_dir / source
    if not source.is_file() or source.stat().st_size > MAX_PROVIDER_BYTES:
        raise ValueError('Provider cache missing or too large; update it in desktop first: ' + name)
    format_name = provider.get('format', 'yaml')
    if format_name == 'mrs':
        if not mihomo_binary:
            raise ValueError('MRS requires --mihomo-binary; raw MRS is never imported on iOS')
        with tempfile.TemporaryDirectory(prefix='ios-mrs-convert-') as temporary:
            output = Path(temporary) / 'rules.txt'
            subprocess.run([str(mihomo_binary), 'convert-ruleset', behavior, 'mrs', str(source), str(output)],
                           check=True, capture_output=True, timeout=30)
            if output.stat().st_size > MAX_PROVIDER_BYTES:
                raise ValueError('Converted provider is too large: ' + name)
            payload = [line.strip() for line in output.read_text().splitlines()
                       if line.strip() and not line.lstrip().startswith('#')]
    elif format_name == 'yaml':
        parsed = yaml.safe_load(source.read_text())
        payload = parsed.get('payload') if isinstance(parsed, dict) else None
    elif format_name == 'text':
        payload = [line.strip() for line in source.read_text().splitlines()
                   if line.strip() and not line.lstrip().startswith('#')]
    else:
        raise ValueError('Unsupported provider format: ' + str(format_name))
    if not isinstance(payload, list) or not payload or any(not isinstance(v, str) for v in payload):
        raise ValueError('Invalid or empty provider payload: ' + name)
    for value in payload:
        if behavior == 'domain':
            kind = 'DOMAIN-SUFFIX' if value.startswith('+.') else 'DOMAIN'
            domain = value[2:] if kind == 'DOMAIN-SUFFIX' else value
            if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', domain):
                raise ValueError('Provider domain pattern needs an exact mobile adapter: ' + name)
            yield f'{kind},{domain},{target}'
        elif behavior == 'ipcidr':
            network = ipaddress.ip_network(value, strict=False)
            kind = 'IP-CIDR6' if network.version == 6 else 'IP-CIDR'
            yield ','.join([kind, str(network), target, *flags])
        else:
            fields = [part.strip() for part in value.split(',')]
            kind = fields[0]
            if kind not in SUPPORTED or kind == 'MATCH':
                raise ValueError('Classical provider needs an explicit mobile adapter: ' + kind)
            yield ','.join([*fields[:2], target, *fields[2:], *flags])


def export(config, proxies, base_dir=Path('.'), mihomo_binary=None):
    mapping = {}
    converted = []
    skipped = 0
    expanded = 0
    for rule in config['rules']:
        parts = [part.strip() for part in rule.split(',')]
        kind = parts[0]
        if kind in SKIPPED:
            skipped += 1
            continue
        if kind not in SUPPORTED and kind != 'RULE-SET':
            raise ValueError('Rule needs an explicit iOS conversion: ' + kind)
        position = 1 if kind == 'MATCH' else 2
        if len(parts) <= position:
            raise ValueError('Malformed rule: ' + kind)
        original = parts[position]
        resolved = leaf(proxies, original)
        target = 'DIRECT' if resolved == 'DIRECT' else 'REJECT' if resolved in {'REJECT', 'REJECT-DROP'} else PLACEHOLDER
        mapping[original] = target
        if kind == 'NETWORK' and (len(parts) != 3 or parts[1].lower() not in {'udp', 'tcp'}):
            raise ValueError('NETWORK requires tcp/udp and no additional flags')
        if kind == 'RULE-SET':
            added = list(provider_rules(config, parts[1], target, parts[position + 1:], Path(base_dir), mihomo_binary))
            expanded += len(added)
            converted.extend(added)
        else:
            parts[position] = target
            converted.append(','.join(parts))
        if len(converted) > MAX_RULES:
            raise ValueError('Expanded policy exceeds the mobile 50000-rule limit; use public YAML providers in General Routing instead')
    for index, rule in enumerate(converted):
        validate_portable_rule(rule)
        if rule.startswith('MATCH,') and index != len(converted) - 1:
            raise ValueError('MATCH must be the final rule')
    if not converted or not converted[-1].startswith('MATCH,'):
        raise ValueError('Desktop rules must end with MATCH')
    return {
        'version': 1,
        'generatedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
        'sourceRuleCount': len(converted) + skipped,
        'sourceTopLevelRuleCount': len(config['rules']),
        'expandedProviderRuleCount': expanded,
        'skippedProcessRuleCount': skipped,
        'policyMap': mapping,
        'rules': converted,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path.home() / 'Library/Application Support/mihomo-party/work/config.yaml')
    parser.add_argument('--socket')
    parser.add_argument('--proxies-json', type=Path, help='Offline GET /proxies JSON for deterministic export')
    parser.add_argument('--mihomo-binary', type=Path, help='Existing desktop core used only for convert-ruleset')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.proxies_json:
        proxies = json.loads(args.proxies_json.read_text())['proxies']
    else:
        candidates = [args.socket] if args.socket else sorted(glob.glob('/tmp/mihomo-party-' + str(os.getuid()) + '-*.sock'), key=os.path.getmtime, reverse=True)
        if not candidates:
            raise SystemExit('No running desktop controller socket found; export refused.')
        proxies = load_proxies(candidates[0])
    binary = args.mihomo_binary
    if binary is None:
        candidate = Path('/Applications/Clash Party.app/Contents/Resources/sidecar/mihomo')
        binary = candidate if candidate.is_file() else shutil.which('mihomo')
    snapshot = export(yaml.safe_load(args.config.read_text()), proxies, args.config.parent, binary)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + '.tmp')
    temporary.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + '\n')
    temporary.replace(args.output)
    print(json.dumps({'rules': len(snapshot['rules']), 'source': snapshot['sourceRuleCount'], 'skipped_desktop_process_rules': snapshot['skippedProcessRuleCount'], 'output': str(args.output)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
