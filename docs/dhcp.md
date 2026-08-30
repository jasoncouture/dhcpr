# DHCP

Optional IPv4 DHCP server. **Off by default** in the container
(`DHCP__ENABLED=false`). Classic DNS does not depend on it.

The configuration section is `Dhcp` (environment `Dhcp__…` or `DHCP__…`;
binding is case-insensitive).

## Enable

```json
"Dhcp": {
  "Enabled": true,
  "Subnets": [
    {
      "CIDR": "192.168.1.0/24",
      "TimeToLiveSeconds": 3600,
      "Enabled": true
    }
  ]
}
```

| Key | Rule |
|-----|------|
| `Enabled` | When false, the hosted service logs and exits (no socket) |
| `Subnets[].CIDR` | IPv4 prefix the server will serve |
| `Subnets[].TimeToLiveSeconds` | Lease lifetime; **must be ≥ 300** |
| `Subnets[].Enabled` | Per-subnet switch |

Validation also requires that **some local NIC** has a unicast address inside
that CIDR. If the process cannot list interfaces (permissions), that check is
skipped and bind-time errors surface later.

Older sample JSON (`Network`, `Gateway`, `AddressRanges`, …) does **not** match
this type. Use `CIDR` / `TimeToLiveSeconds` / `Enabled`.

## Socket

Binds **UDP 67** on `0.0.0.0` (`IP_PKTINFO` so the receiving interface is
known). Needs `NET_BIND_SERVICE` or root, and must see broadcasts on that L2
segment (host network, or a CNI that delivers DHCP — ClusterIP will not).

The image does not `EXPOSE` 67; turn DHCP on only where you intend to own the
LAN.

## What it does

Incoming DISCOVER/REQUEST packets are parsed and queued. The server matches the
receiving interface to a configured subnet and issues leases from that prefix.
Lease time is `TimeToLiveSeconds`.

This is a small in-process server, not a replacement for Kea/ISC on a large
campus. Prefer it when the same box already speaks DNS for that LAN.

## Kubernetes

The Helm chart does **not** publish UDP/67. If you need DHCP in-cluster, add a
hostNetwork / hostPort Deployment yourself and set `Dhcp__Enabled=true` plus
valid subnets. Most clusters should leave it off.
