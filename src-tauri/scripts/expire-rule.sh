#!/bin/bash
# Temporary rule expiry script
# Deployed to remote hosts to remove expired temporary rules
# Usage: expire-rule.sh <chain> <rule-spec>
set -e

CHAIN="$1"
shift
RULE_SPEC="$@"

if [ -z "$CHAIN" ] || [ -z "$RULE_SPEC" ]; then
    echo "Usage: expire-rule.sh <chain> <rule-spec...>" >&2
    exit 1
fi

# Remove the rule (IPv4)
/usr/sbin/iptables -w 5 -D "$CHAIN" $RULE_SPEC 2>/dev/null || true

# Remove the rule (IPv6) if applicable
/usr/sbin/ip6tables -w 5 -D "$CHAIN" $RULE_SPEC 2>/dev/null || true
