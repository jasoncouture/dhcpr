# Operations

## Ports

| Port | Protocol | Role |
|------|----------|------|
| 8080 | TCP HTTP | UI (dev/proxy), `/health`, `/metrics`, `/dns-query`, DynDNS. Always on in the image |
| 53 | UDP/TCP | Classic DNS |
| 443 | TCP TLS | DoH when `TLS:Enabled` / `secureDns`. UI is 404 on the DoH hostname. |
| 853 | TCP TLS | DNS-over-TLS |
| 67 | UDP | DHCP (only if `Dhcp:Enabled`) |
| 11111 / 30000 | TCP | Orleans silo / gateway (cluster-internal) |

Dockerfile `EXPOSE`s 8080, 443, 853 (not 53 — Helm and compose still map it).
The image sets `DOTNET_URLS=http://+:8080` and `DataPath=/data`. Published
binaries load `appsettings` from `AppContext.BaseDirectory` (next to the
exe), not the repo tree.

## Health

`GET /health` — ASP.NET health checks.

The DNS check (`DnsResolveHealthCheck`) resolves every
`DNS:HealthCheck:Domains` entry **through the DNS pipeline** (A and AAAA).
Timeout is `TimeoutSeconds` (1–120, default 5) for the whole batch.

| Config | Result |
|--------|--------|
| `Enabled: false` | Healthy |
| `Domains` empty | Healthy |
| Any domain fails both A and AAAA | Unhealthy |

Helm probes this on **8080**. Put a name you expect this resolver to answer
(an overlay record is fine). Do not list a name that only exists on a flaky
upstream unless you want the pod to flap.

In-process probes use client `127.0.0.1:0` / `[::1]:0` so they do not appear
on the live-query page.

## Metrics

`GET /metrics` — OpenTelemetry Prometheus exporter. No auth.

Meter `Dhcpr.Dns`, counter `dns.queries` (`{query}`).

Labels:

| Label | Values |
|-------|--------|
| `cache_hit` | true / false |
| `error` | true if RCODE is not NoError |
| `rcode` | `NoError`, `NxDomain`, `ServFail`, … |
| `query_type` | `A`, `AAAA`, `NS`, … |
| `query_class` | usually `IN` |
| `answered_by` | middleware name, or `resolver` |

Directed internal hops (`BypassCache`) are not counted. Blackhole and NOTIMP
**are** counted.

Chart `serviceMonitor` scrapes this on the `http` port.

## Data directory

`DataPath` (image `/data`, PVC in Helm):

```
{DataPath}/
  settings.json              # UI-saved DNS + DynDNS knobs
  dynamic-dns.json           # DynDNS address map
  dataprotection-keys/       # cookie encryption — share across replicas
  cache/
    root-servers.txt
    root.zone
  zones/
    **/*.bind                # authoritative zones
```

Back up `settings.json`, `dynamic-dns.json`, `zones/`, and
`dataprotection-keys/`. `cache/` is rebuilt from InterNIC on the next start
if `Addresses` is empty (the `Download` flag is unused).

## Logging

Console, single-line, with scopes. Useful categories:

- `Dhcpr.*` — DNS/DHCP/server
- `Dhcpr.Server.Orleans.LiveQueries` — default Warning in sample appsettings
- `Orleans` — default Warning

Invalid `settings.json` on disk is logged and ignored (in-memory last-good or
appsettings seed).

## Versions

[`version.json`](../version.json) is Nerdbank.GitVersioning (`2.0-alpha` on
`main`). `dotnet build` at a git checkout stamps the assembly.

Docker builds **cannot** see `.git` (dockerignored) and do not restore the
NBGV package. CI computes versions and passes bake args:

| Build-arg | MSBuild |
|-----------|---------|
| `VERSION` | `Version` |
| `ASSEMBLY_VERSION` | `AssemblyVersion` |
| `ASSEMBLY_FILE_VERSION` | `FileVersion` |
| `INFORMATIONAL_VERSION` | `InformationalVersion` |

Those `ARG`s are declared **after** `dotnet restore`. Declaring `ARG VERSION`
before restore exports `VERSION` into the environment; MSBuild treats it as
`$(Version)` and restore dies with MSB4181.

Local `docker build` without args stamps `1.0.0`. The UI footer shows
`InformationalVersion`.

Helm `charts/dhcpr/Chart.yaml` `appVersion` is rewritten in CI to the image
tag.

## Process failure

`HostOptions.BackgroundServiceExceptionBehavior = StopHost`. A crashing hosted
service (DNS listener, zone loader, …) takes the process down so the kubelet
restarts the pod.

`DNS`, `TLS`, and `DataPath` use `ValidateOnStart` — bad listen URIs, empty
`ListenAddresses`, or `TLS:Enabled` without PEM paths exit immediately.

## Multi-replica

- Share `/data` (RWX) or accept split-brain settings/zones/keys
- HTTPRoute sticky cookie for Blazor
- Orleans labels already on the Deployment for cluster membership
- Cache is per process (Orleans publishes invalidation events)

## Local image

[`compose.yaml`](../compose.yaml) maps host **8080** and **65353→53**, with a
named volume on `/data`. It does not pass TLS or listen-address overrides
(the image’s Production appsettings already bind 53 inside the container).

```bash
docker compose up --build
dig @127.0.0.1 -p 65353 example.com A
```

Or without compose:

```bash
docker build -t dhcpr .
docker run --rm -p 8080:8080 -p 53:53/udp -p 53:53/tcp \
  -e DNS__ListenAddresses__0=udp://0.0.0.0:53 \
  -e DNS__ListenAddresses__1=tcp://0.0.0.0:53 \
  dhcpr
```

Add `-p 443:443 -p 853:853` and `TLS__*` when you have a cert. Do not publish
8080 to the internet if DynDNS/DoH-on-HTTP should stay internal.

## License

[AGPL-3.0](../LICENSE). Official git: https://git.alertr.info/jasoncouture/dhcpr
