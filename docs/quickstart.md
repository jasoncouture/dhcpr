# Quickstart

Requires the [.NET 10 SDK](https://dot.net/). Port 53 needs extra privileges;
development uses **65353** so you can run unprivileged.

## Clone the official repo

```bash
git clone https://git.alertr.info/jasoncouture/dhcpr.git
cd dhcpr
```

GitHub (`github.com/jasoncouture/dhcpr`) is a mirror. Do not open issues or PRs there.

## Build and test

```bash
dotnet test
```

## Run locally

```bash
dotnet run --project src/Dhcpr.Server
```

That profile (`src/Dhcpr.Server/Properties/launchSettings.json`) binds:

| What | Where |
|------|--------|
| Operator UI | [http://localhost:5187](http://localhost:5187) |
| DNS UDP/TCP | `127.0.0.1:65353` and `[::1]:65353` |

The UI is behind OpenID Connect (Keycloak). You need a `dns-user` or `dns-admin`
role (see [UI](ui.md)). DNS itself does not require login.

## Send a query

```bash
dig @127.0.0.1 -p 65353 example.com A
```

You should get an answer and see the query on the live-query page (loopback
clients with a real source port are shown; in-process health probes are not).

## Minimal config to listen on 53

Environment variables override `appsettings*.json`. Double underscore is nesting:

```bash
export DNS__ListenAddresses__0=udp://0.0.0.0:53
export DNS__ListenAddresses__1=tcp://0.0.0.0:53
export DNS__ListenAddresses__2='udp://[::]:53'
export DNS__ListenAddresses__3='tcp://[::]:53'
```

`DNS:ListenAddresses` is required and must be non-empty. Allowed schemes are
`udp://`, `tcp://`, and `interface://` (every unicast address on that NIC, both
UDP and TCP). There is no `tls://` scheme; DoT is the `TLS` section
([encrypted DNS](encrypted-dns.md)).

## Next

- [Configuration](configuration.md) — routes, records, DNSSEC, TLS
- [Helm](helm.md) — run it on Kubernetes
- [Operations](operations.md) — `/health`, `/metrics`, `DataPath`
