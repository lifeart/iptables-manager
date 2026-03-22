# IP Lists

IP Lists (formerly "Address Groups") are reusable collections of IP addresses referenced in rules across all hosts. They use **ipset** under the hood for performance — scaling to thousands of IPs without degradation.

## Why IP Lists?

Instead of:
```
Allow SSH from 83.12.44.0/24
Allow SSH from 10.0.0.0/8
Allow SSH from 172.16.5.0/24
```

Create an IP List "Office IPs" and write:
```
Allow SSH from Office IPs
```

One rule, easier to read, and when IPs change, update in one place.

## Terminology

"IP Lists" (not "Address Groups") to avoid confusion with host groups. The sidebar shows:
- **Groups** = collections of servers that share rules
- **IP Lists** = collections of IP addresses used in rules

## Managing IP Lists

Accessible from the sidebar "IP Lists" section or from any source/destination dropdown:

```
┌─────────────────────────────────────────────────────────┐
│  IP Lists                                    [+ New]    │
│  ─────────────────────────────────────────────────────  │
│                                                         │
│  🏢  Office IPs                          3 addresses    │
│      83.12.44.0/24, 10.0.0.0/8, 172.16.5.0/24         │
│      Used in: 4 rules across 3 hosts                    │
│                                                         │
│  🖥️  App Servers                         2 addresses    │
│      10.0.1.1, 10.0.1.2                                │
│      Used in: 2 rules across 2 hosts                    │
│                                                         │
│  📊  Monitoring                          1 address      │
│      10.0.10.0/24                                       │
│      Used in: 5 rules across 5 hosts                    │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Creating an IP List

```
┌─────────────────────────────────────────────────────────┐
│  New IP List                                         ×  │
│                                                         │
│  Name     [Office IPs                          ]        │
│                                                         │
│  Addresses                                              │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 83.12.44.0/24                              [×]   │  │
│  │ 10.0.0.0/8                                 [×]   │  │
│  │ 172.16.5.0/24                              [×]   │  │
│  │                                                   │  │
│  │ [+ Add address]                                   │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│  💡 Type a managed host name (e.g., "web-01") to        │
│     add its IP automatically.                           │
│                                                         │
│                      [Cancel]    [Create IP List]       │
└─────────────────────────────────────────────────────────┘
```

### Validation

```
Valid:    192.168.1.1
Valid:    10.0.0.0/8
Valid:    2001:db8::/32           (IPv6)
Valid:    web-01                  (resolves to managed host IP)
Invalid: 999.999.999.999         → "Invalid IP address"
Invalid: 10.0.0.0/33             → "CIDR prefix must be 0-32"
```

## Technical Implementation

IP Lists use **ipset** on the remote host:

```bash
# Created automatically:
ipset create office_ips hash:net
ipset add office_ips 83.12.44.0/24
ipset add office_ips 10.0.0.0/8

# Referenced in iptables:
iptables -A INPUT -p tcp --dport 22 -m set --match-set office_ips src -j ACCEPT
```

This scales to thousands of IPs without creating thousands of individual iptables rules.

If ipset is not available on the host, the app falls back to inline address lists (individual rules per IP) with a note:

```
  ℹ️ ipset not available on web-01.
  IP Lists will use individual rules (slower for large lists).
  [Install ipset]  [Continue without]
```

### Performance Auto-Migration

When a host accumulates 20+ individual block rules (from Quick Block or Activity tab), the app automatically suggests migrating to a single ipset-backed "Blocked IPs" list:

```
  💡 You have 23 individual block rules.
  Combining them into an IP List improves performance.

  [Combine into "Blocked IPs" list]  [Keep individual rules]
```

## Corner Cases

### Deleting an IP List That's In Use

```
  ⚠️  "Office IPs" is used in 4 rules across 3 hosts:

  web-01: Allow SSH from Office IPs
  web-02: Allow SSH from Office IPs
  db-01:  Allow SSH from Office IPs
  db-01:  Allow PostgreSQL from Office IPs

  Deleting this list will remove these rules.

  [Delete list and rules]  [Cancel]
```

### Editing an IP List Updates All Rules

```
  Updating "Office IPs" will affect 4 rules across 3 hosts.

  Changes:
  + Adding 192.168.50.0/24
  − Removing 172.16.5.0/24

  ipsets will be updated on each host on next Apply.

  [Update list]  [Cancel]
```

### Empty IP List

```
  ⚠️  "Office IPs" has no addresses.
  Rules using this list won't match any traffic.

  [Add addresses]  [Delete list]
```

### Managed Host IP Changes

```
  💡  web-01's IP changed from 10.0.1.1 to 10.0.1.5.
  The "App Servers" IP List has been updated automatically.

  Rules using this list will need to be re-applied.
```

### Nested IP Lists

Not supported. Keep it simple — IP Lists contain only IP addresses, CIDRs, and managed host references.
