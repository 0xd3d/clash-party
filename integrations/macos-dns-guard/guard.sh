#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Foreground, session-only PF guard. No global flush, pf.conf edits or service installation.
set -eu
[ "$(/usr/bin/uname -s)" = Darwin ] || { echo 'macOS only'; exit 1; }
[ "$(/usr/bin/id -u)" = 0 ] || { echo 'Run this reviewed script with sudo.'; exit 1; }
app_pid=${1:-}
case "$app_pid" in ''|*[!0-9]*) echo 'Expected the current Clash Party main-process PID'; exit 1;; esac
app_path='/Applications/Clash Party.app/Contents/MacOS/Clash Party'
actual=$(/bin/ps -p "$app_pid" -o comm= | /usr/bin/sed 's/^ *//')
[ "$actual" = "$app_path" ] || { echo 'PID does not belong to the installed application'; exit 1; }
owner=$(/bin/ps -p "$app_pid" -o uid= | /usr/bin/tr -d ' ')
[ "$owner" = "${SUDO_UID:-$owner}" ] || { echo 'Application belongs to another user'; exit 1; }
/usr/bin/nc -z -w 2 127.0.0.1 53 || { echo 'Local TCP DNS must be ready before enabling this guard'; exit 1; }
# A scoped resolver can override localhost even after all adapters were migrated.
# Do not silently delete corporate/admin resolver files or enable a guard that would break them.
for resolver in /etc/resolver/*; do
  [ -f "$resolver" ] || continue
  if /usr/bin/awk '$1 == "nameserver" && $2 !~ /^127[.]/ && $2 != "::1" { bad=1 } END { exit !bad }' "$resolver"; then
    echo "Conflicting domain-specific DNS override: $resolver" >&2
    echo 'Review and back up this override before enabling the DNS guard. No PF rules changed.' >&2
    exit 1
  fi
done
umask 077
work=$(/usr/bin/mktemp -d /private/tmp/clash-party-pf.XXXXXX)
suffix=${work##*.}
anchor="com.apple/000.ClashPartyDNS.$owner.$app_pid.$suffix"
token=''
loaded=false
cleanup() {
  trap - EXIT HUP INT TERM
  failed=false
  if [ -z "$token" ] && [ -f "$work/enable-output" ]; then
    token=$(/usr/bin/awk '/Token[[:space:]]*:/ { print $3 }' "$work/enable-output" | /usr/bin/tail -1)
    case "$token" in *[!0-9]*) token='';; esac
  fi
  if [ "$loaded" = true ]; then
    /sbin/pfctl -a "$anchor" -F rules || failed=true
  fi
  if [ -n "$token" ]; then /sbin/pfctl -X "$token" || failed=true; fi
  if [ "$failed" = true ]; then
    echo "Cleanup incomplete. Preserve evidence and inspect this anchor: $anchor" >&2
  else
    /bin/rm -f "$work/rules" "$work/root-rules" "$work/enable-output"
    /bin/rmdir "$work"
    echo 'Only this DNS guard anchor and PF reference were released.'
  fi
}
trap cleanup EXIT HUP INT TERM
/sbin/pfctl -sr > "$work/root-rules"
/usr/bin/grep -Eq '^anchor "com[.]apple/[*]"' "$work/root-rules" || {
  echo 'The system com.apple/* filter anchor is not referenced. No rules changed.'; exit 1;
}
printf '%s\n' 'block return out quick on ! lo0 proto { udp tcp } from any to any port 53 label "ClashPartyDNSGuard"' > "$work/rules"
/sbin/pfctl -a "$anchor" -nf "$work/rules"
echo 'Existing PF interface skip flags (must be considered during live verification):'
/sbin/pfctl -s Interfaces -v
# Acquire only our own enable reference; never use pfctl -d.
/sbin/pfctl -E > "$work/enable-output" 2>&1
token=$(/usr/bin/awk '/Token[[:space:]]*:/ { print $3 }' "$work/enable-output" | /usr/bin/tail -1)
case "$token" in ''|*[!0-9]*) echo 'No valid PF reference token returned; refusing to load rules'; exit 1;; esac
loaded=true
/sbin/pfctl -a "$anchor" -f "$work/rules"
/sbin/pfctl -s info
/sbin/pfctl -a "$anchor" -sr
echo "ACTIVE: $anchor"
echo 'Keep this terminal open. Ctrl-C removes only this guard.'
echo 'DNS on lo0 and HTTPS/DoH remain allowed. Non-loopback plain DNS is blocked.'
echo 'Existing PF connection states are preserved; verify with fresh DNS sockets.'
while /bin/kill -0 "$app_pid" 2>/dev/null; do
  current=$(/bin/ps -p "$app_pid" -o comm= | /usr/bin/sed 's/^ *//')
  [ "$current" = "$app_path" ] || break
  /bin/sleep 1
done
