# Public resolver

Public instances of this software:

| Hostname | IPv4 | IPv6 |
|---|---|---|
| `dns.alertr.info` | `23.162.92.54` | `2602:81e:9004::4` |
| `dns.instigaterevolution.com` | `23.162.92.1` | `2602:81e:9002::1` |

Each name’s A and AAAA serve that resolver. Pin the IPs if you do not want to
depend on another resolver to look up the hostname.

| Port | Protocol |
|------|----------|
| 53 | Classic DNS, UDP and TCP. UDP answers over 1232 bytes are TC (retry on TCP). UDP and TCP are rate-limited (REFUSED, then silence). DoT and DoH are not. |
| 853 | DNS-over-TLS (RFC 7858). Use the hostname you queried as the TLS name (certificate SAN/CN). |
| 443 | HTTPS — DNS-over-HTTPS at `/dns-query` (RFC 8484) |

These names are DoH-only on HTTPS: paths other than `/dns-query` return
**404**. The operator UI is not on them. `/health` and `/metrics` stay
on cluster-internal HTTP 8080.

## Classic DNS

```bash
dig @dns.alertr.info example.com A
dig @23.162.92.54 example.com A
dig @2602:81e:9004::4 example.com AAAA

dig @dns.instigaterevolution.com example.com A
dig @23.162.92.1 example.com A
dig @2602:81e:9002::1 example.com AAAA
```

## DNS-over-TLS

TLS hostname must match the certificate SAN/CN for the name you use.

```bash
dig @dns.alertr.info +tls example.com A
dig @dns.instigaterevolution.com +tls example.com A
```

Knot `kdig`:

```bash
kdig @dns.alertr.info +tls +tls-host=dns.alertr.info example.com A
kdig @dns.instigaterevolution.com +tls +tls-host=dns.instigaterevolution.com example.com A
```

Stub examples (`dns.alertr.info`; swap hostname and IPs for
`dns.instigaterevolution.com`):

- **systemd-resolved** (`resolved.conf`): `DNS=23.162.92.54#dns.alertr.info` and/or `DNS=2602:81e:9004::4#dns.alertr.info`, `DNSOverTLS=yes`
- **Unbound**: `forward-addr: 23.162.92.54@853#dns.alertr.info`
- **Android**: Private DNS hostname `dns.alertr.info` or `dns.instigaterevolution.com`

## DNS-over-HTTPS

`POST`/`GET` `https://dns.alertr.info/dns-query` or
`https://dns.instigaterevolution.com/dns-query` — see
[encrypted DNS](encrypted-dns.md).

DDR: query `_dns.resolver.arpa` `SVCB` at the resolver for the advertised DoT
(`alpn=dot`) and DoH (`alpn=h2`, `dohpath=/dns-query{?dns}`) records.

## How it is published

The Helm chart in this repo only creates a ClusterIP. The public VIPs
(`23.162.92.54` / `2602:81e:9004::4` and `23.162.92.1` / `2602:81e:9002::1`)
are separate LoadBalancers in front of the `https` and `dns-tls` Service ports
(and classic 53). Those objects are not in this repository.
