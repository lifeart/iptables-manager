#!/bin/bash
set -e
BACKUP_V4="/var/lib/traffic-rules/backup.v4"
BACKUP_V6="/var/lib/traffic-rules/backup.v6"
HMAC_FILE="${BACKUP_V4}.hmac"
SECRET_FILE="/var/lib/traffic-rules/.hmac_secret"

# Verify HMAC
if [ -f "$SECRET_FILE" ]; then
    # Host is provisioned — HMAC check is mandatory
    if [ ! -f "$HMAC_FILE" ]; then
        echo "HMAC file missing — refusing to restore potentially tampered backup" >&2
        exit 1
    fi
    EXPECTED=$(cat "$HMAC_FILE")
    # Note: The secret briefly appears in /proc/PID/cmdline but the script runs
    # as root and completes in milliseconds; the secret file is already root-only (0600).
    ACTUAL=$(openssl dgst -sha256 -hmac "$(cat "$SECRET_FILE")" "$BACKUP_V4" 2>/dev/null | awk '{print $NF}')
    if [ "$EXPECTED" != "$ACTUAL" ]; then
        echo "HMAC verification failed" >&2
        exit 1
    fi
fi
# If SECRET_FILE doesn't exist, host is unprovisioned — skip HMAC check

# Restore (filtered backup — only TR- chains, safe with --noflush)
if [ -f "$BACKUP_V4" ]; then
    /usr/sbin/iptables-restore -w 5 --noflush --counters < "$BACKUP_V4"
fi
if [ -f "$BACKUP_V6" ]; then
    /usr/sbin/ip6tables-restore -w 5 --noflush --counters < "$BACKUP_V6"
fi

# Cleanup
rm -f "$BACKUP_V4" "$BACKUP_V6" "$HMAC_FILE"
