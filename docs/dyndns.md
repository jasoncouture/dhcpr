# Dynamic DNS

HTTP **dyndns2**-style updates (not RFC 2136 DNS UPDATE). Compatible with
clients that speak `GET /nic/update` (ddclient, many routers, `inadyn`).

Answers for those names are an authoritative overlay: they win over forwarders
and recursion, are not cached, and require the name to already exist in a
loaded zone file.

## Configuration

Root key `DynamicDns` (also editable at `/settings/dynamic-dns`).

| Key | Default | Rule |
|-----|---------|------|
| `Enabled` | `true` | When false, every update returns `dnserr` |
| `Username` | | Required when enabled |
| `Password` | | Required when enabled |
| `TtlSeconds` | `60` | 1–86400 |
| `TrustForwardedFor` | `false` | If `myip` is omitted, use the first `X-Forwarded-For` hop |

The sample `appsettings.json` has `Enabled: true` and a placeholder password.
Change it before exposing the HTTP port.

State is `{DataPath}/dynamic-dns.json`.

## Endpoints

Both are the same handler. **No OIDC** — HTTP Basic only.

```
GET /nic/update?hostname=<name>[&myip=<addr>]
GET /v3/update?hostname=<name>[&myip=<addr>]
Authorization: Basic base64(username:password)
```

`hostname` may be a comma-separated list. Each name is updated independently;
the body is one status line per name.

`myip` may be IPv4, IPv6, or `v4,v6`. If omitted, the TCP peer address is used
(or the first `X-Forwarded-For` hop when `TrustForwardedFor` is true).

Response `Content-Type` is `text/plain; charset=utf-8`.

## Status lines

| Body | Meaning |
|------|---------|
| `good <ip>` | Record written (or IPv4+IPv6 pair) |
| `nochg <ip>` | Same addresses already stored |
| `badauth` | Missing/wrong Basic credentials |
| `notfqdn` | Empty or unparseable hostname |
| `nohost` | Name is not in any loaded `{DataPath}/zones/**/*.bind` zone |
| `dnserr` | Disabled, no usable address, or store failure |

`nohost` is the usual surprise: create the zone (and a placeholder A/AAAA) first,
then point the updater at that FQDN.

## Client examples

```bash
curl -fsS -u 'user:pass' \
  'https://dns.example.com/nic/update?hostname=host.home.arpa&myip=203.0.113.10'
```

ddclient:

```
protocol=dyndns2
use=web
server=dns.example.com
ssl=yes
login=user
password=pass
host.home.arpa
```

## DNS side

`DynamicDnsMiddleware` answers A/AAAA for exact names in the store, with AA set.
TTL is `TtlSeconds`. Other types fall through to the rest of the pipeline.
