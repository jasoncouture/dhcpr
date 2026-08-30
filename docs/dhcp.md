# DHCP

Optional IPv4 DHCP server. **Off by default** in the container
(`DHCP__ENABLED=false`). Classic DNS does not depend on it.

The configuration section is `Dhcp` (environment `Dhcp__…` or `DHCP__…`;
binding is case-insensitive).

## What actually works

`Dhcp:Enabled` is the only operator switch that is honored. When false, the
hosted service logs `"DHCP server is disabled."` and does not bind a socket.
When true, it binds **UDP 67** on `0.0.0.0` (`IP_PKTINFO` so the receiving
interface is known).

The lease pool is **hardcoded** in `AddDhcp`: `10.0.0.100`–`10.0.0.200` on
`10.0.0.0/24` (gateway `10.0.0.1`). `Dhcp:Subnets` is bound from JSON but not
wired into that pool. Sample appsettings still use leftover keys (`Network`,
`Gateway`, `AddressRanges`, …) that do not map onto `SubnetConfiguration`
(`CIDR`, `TimeToLiveSeconds`, `Enabled`) anyway.

Treat this as a lab stub, not something to point at a real LAN. The type
exists for a future subnet model; do not expect `Subnets` to change the
addresses handed out.

## Socket

Needs `NET_BIND_SERVICE` or root, and must see broadcasts on that L2 segment
(host network, or a CNI that delivers DHCP — ClusterIP will not). The image
does not `EXPOSE` 67.

`appsettings.Production.json` sets `Dhcp:Enabled` true; the Dockerfile
overrides that with `DHCP__ENABLED=false`.

## Kubernetes

The Helm chart does **not** publish UDP/67. Leave it off.
