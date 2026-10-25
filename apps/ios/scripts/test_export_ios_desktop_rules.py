#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('ios_rules', Path(__file__).with_name('export_ios_desktop_rules.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PortablePolicyExportTests(unittest.TestCase):
    def test_network_and_yaml_provider_preserve_order_and_strip_nodes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'foreign.yaml').write_text('payload:\n  - +.claude.ai\n  - exact.example.org\n')
            config = {'proxies': [{'uuid': 'must-not-export'}], 'rules': ['NETWORK,udp,Route', 'RULE-SET,foreign,Route', 'DOMAIN-SUFFIX,qq.com,DIRECT', 'MATCH,Route'],
                      'rule-providers': {'foreign': {'type': 'file', 'behavior': 'domain', 'path': 'foreign.yaml', 'format': 'yaml'}}}
            result = module.export(config, {'Route': {'now': 'Node'}, 'Node': {}}, path)
            self.assertEqual(result['rules'], ['NETWORK,udp,__IOS_PROXY__', 'DOMAIN-SUFFIX,claude.ai,__IOS_PROXY__', 'DOMAIN,exact.example.org,__IOS_PROXY__', 'DOMAIN-SUFFIX,qq.com,DIRECT', 'MATCH,__IOS_PROXY__'])
            self.assertNotIn('must-not-export', str(result))
            self.assertGreaterEqual(result['sourceRuleCount'], len(result['rules']))

    def test_mrs_uses_existing_core_converter_without_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'foreign.mrs').write_bytes(b'fixture')
            config = {'rules': ['RULE-SET,foreign,Route', 'MATCH,Route'], 'rule-providers': {'foreign': {'type': 'file', 'behavior': 'domain', 'format': 'mrs', 'path': 'foreign.mrs'}}}
            def convert(args, **kwargs):
                self.assertEqual(args[:4], ['/opt/example/mihomo', 'convert-ruleset', 'domain', 'mrs'])
                self.assertNotIn('shell', kwargs)
                Path(args[-1]).write_text('+.claude.ai\n')
            with patch.object(module.subprocess, 'run', side_effect=convert):
                result = module.export(config, {'Route': {'now': 'Node'}, 'Node': {}}, path, '/opt/example/mihomo')
            self.assertEqual(result['rules'][0], 'DOMAIN-SUFFIX,claude.ai,__IOS_PROXY__')
            with self.assertRaisesRegex(ValueError, 'MRS requires'):
                module.export(config, {'Route': {'now': 'Node'}, 'Node': {}}, path)

    def test_classical_provider_rejects_network_flags_before_export(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'rules.yaml').write_text("payload:\n  - NETWORK,udp,no-resolve\n")
            config = {'rules': ['RULE-SET,foreign,Route', 'MATCH,Route'], 'rule-providers': {'foreign': {'behavior': 'classical', 'path': 'rules.yaml'}}}
            with self.assertRaisesRegex(ValueError, 'NETWORK requires'):
                module.export(config, {'Route': {'now': 'Node'}, 'Node': {}}, path)

    def test_unsupported_patterns_and_network_flags_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'foreign.yaml').write_text("payload:\n  - '*.example.org'\n")
            config = {'rules': ['RULE-SET,foreign,Route', 'MATCH,Route'], 'rule-providers': {'foreign': {'behavior': 'domain', 'path': 'foreign.yaml'}}}
            with self.assertRaisesRegex(ValueError, 'exact mobile adapter'):
                module.export(config, {'Route': {'now': 'Node'}, 'Node': {}}, path)
        with self.assertRaisesRegex(ValueError, 'NETWORK requires'):
            module.export({'rules': ['NETWORK,udp,DIRECT,no-resolve', 'MATCH,DIRECT']}, {})


if __name__ == '__main__':
    unittest.main()
