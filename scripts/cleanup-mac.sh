#!/bin/bash
set -euo pipefail

echo "=== Clash Party Cleanup Tool ==="
echo "This script will remove all Clash Party related files and services."
read -p "Are you sure you want to continue? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

# Recovery must happen before deleting the app, journals or the only recovery tool.
# This script is never called automatically by the application or CI.
if /usr/bin/pgrep -f '^/Applications/Clash Party[.]app/Contents/MacOS/Clash Party( |$)' >/dev/null; then
    echo "Quit Clash Party normally before cleanup so it can restore system DNS." >&2
    exit 1
fi
cleanup_uid="${SUDO_UID:-$(/usr/bin/id -u)}"
if [[ "$cleanup_uid" == 0 ]]; then
    echo "Run this cleanup as the intended desktop user, not a root login." >&2
    exit 1
fi
cleanup_user="$(/usr/bin/id -un "$cleanup_uid")"
cleanup_home="$(/usr/bin/dscl . -read "/Users/$cleanup_user" NFSHomeDirectory | /usr/bin/sed 's/^NFSHomeDirectory: //')"
if [[ "$cleanup_home" != /Users/* || "$cleanup_home" == /Users/Shared ]]; then
    echo "Cannot safely identify the desktop user's home; nothing removed." >&2
    exit 1
fi
dns_journal="$cleanup_home/Library/Application Support/mihomo-party/system-dns-state.json"
if [[ -e "$dns_journal" ]]; then
    saved_services="$(/usr/bin/plutil -extract services json -o - "$dns_journal")"
    if [[ "$(printf '%s' "$saved_services" | /usr/bin/tr -d '[:space:]')" != '[]' ]]; then
        echo "System DNS recovery is pending. Open and quit Clash Party normally before cleanup; journals preserved." >&2
        exit 1
    fi
fi
guard_tool=/Library/PrivilegedHelperTools/party.mihomo.dns-guard
guard_state=/private/var/db/party.mihomo.dns-guard
if [[ -x "$guard_tool" ]]; then
    other_records="$(sudo /usr/bin/find "$guard_state" -maxdepth 1 -name 'uid-*.json' ! -name "uid-$cleanup_uid.json" -print 2>/dev/null || true)"
    if [[ -n "$other_records" ]]; then
        echo "Other users have guard recovery records. Administrator recovery is required before uninstalling this shared app." >&2
        exit 1
    fi
    sudo "$guard_tool" stop --uid "$cleanup_uid"
    sudo /bin/rm -f "$guard_state/uid-$cleanup_uid.json"
    # Retain unrelated state files; remove only this tool after its successful fixed-purpose recovery.
    sudo /bin/rm -f "$guard_tool"
elif [[ -d "$guard_state" ]]; then
    echo "Native guard recovery tool is missing. Reinstall it before cleanup; recovery state preserved." >&2
    exit 1
fi

# Stop and unload services
echo "Stopping services..."
sudo launchctl unload /Library/LaunchDaemons/party.mihomo.helper.plist 2>/dev/null || true

# Remove files
echo "Removing files..."
sudo rm -f /Library/LaunchDaemons/party.mihomo.helper.plist
sudo rm -f /Library/PrivilegedHelperTools/party.mihomo.helper
sudo rm -rf "/Applications/Clash Party.app"
sudo rm -rf "/Applications/Clash\\ Party.app"
sudo rm -rf "$cleanup_home/Library/Application Support/mihomo-party"
sudo rm -rf "$cleanup_home/Library/Caches/mihomo-party"
sudo rm -f "$cleanup_home/Library/Preferences/party.mihomo.app.helper.plist"
sudo rm -f "$cleanup_home/Library/Preferences/party.mihomo.app.plist"

echo "Cleanup complete. Please restart your computer to complete the process."
