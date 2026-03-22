#!/bin/bash
set -e
BACKUP_V4="/var/lib/traffic-rules/backup.v4"
BACKUP_V6="/var/lib/traffic-rules/backup.v6"
HMAC_FILE="${BACKUP_V4}.hmac"
SECRET_FILE="/var/lib/traffic-rules/.hmac_secret"

# Verify HMAC
if [ -f "$HMAC_FILE" ] && [ -f "$SECRET_FILE" ]; then
    SECRET=$(cat "$SECRET_FILE")
    EXPECTED=$(cat "$HMAC_FILE")
    ACTUAL=$(openssl dgst -sha256 -hmac "$SECRET" "$BACKUP_V4" | awk '{print $NF}')
    if [ "$EXPECTED" != "$ACTUAL" ]; then
        echo "HMAC verification failed" >&2
        exit 1
    fi
fi

# Restore (filtered backup — only TR- chains, safe with --noflush)
if [ -f "$BACKUP_V4" ]; then
    /usr/sbin/iptables-restore -w 5 --noflush --counters < "$BACKUP_V4"
fi
if [ -f "$BACKUP_V6" ]; then
    /usr/sbin/ip6tables-restore -w 5 --noflush --counters < "$BACKUP_V6"
fi

# Cleanup
rm -f "$BACKUP_V4" "$BACKUP_V6" "$HMAC_FILE"
