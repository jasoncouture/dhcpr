# dhcpr

**Official source: [git.alertr.info/jasoncouture/dhcpr](https://git.alertr.info/jasoncouture/dhcpr).**
GitHub is a read-only mirror. Issues, PRs, and CI belong on git.alertr.info.

Recursive DNS resolver (and optional DHCP server) with a small operator UI.
.NET 10, in-process DoT/DoH, validating DNSSEC, and a Helm chart for Kubernetes.

**How to use it:** [docs/](docs/README.md) — start with the
[quickstart](docs/quickstart.md). Public resolvers:
**`dns.alertr.info`** (`23.162.92.54` / `2602:81e:9004::4`) and
**`dns.instigaterevolution.com`** (`23.162.92.1` / `2602:81e:9002::1`);
see [docs/public-resolver.md](docs/public-resolver.md).

## What it does

- Classic DNS on UDP/TCP 53
- DNS-over-TLS (RFC 7858) on 853 and DNS-over-HTTPS (RFC 8484) on `/dns-query`
- DDR: SVCB at `_dns.resolver.arpa` advertises DoT (`alpn=dot`) and DoH (`alpn=h2`)
- Validating recursive DNSSEC
- Conditional forwarders (`DNS:Routes`), overlay records, blackhole suffixes, HTTP DynDNS
- Blazor UI (live queries, settings), Prometheus `/metrics`, and OpenTelemetry (OTLP via `OTEL_*`)
- Optional DHCP (off by default)

## Build and run

Requires the .NET 10 SDK. Details: [quickstart](docs/quickstart.md).

```bash
dotnet test
dotnet run --project src/Dhcpr.Server
```

Development listens on `http://localhost:5187` (UI) and DNS `127.0.0.1:65353` /
`[::1]:65353`. Production images listen on `8080` (HTTP probes/UI), `53`, `443`,
and `853`.

## Configuration

ASP.NET Core (`appsettings.json`, environment variables). Full key reference:
[docs/configuration.md](docs/configuration.md).

DNS bind addresses are `DNS:ListenAddresses` (`udp://`, `tcp://`,
`interface://` only). TLS is a separate `TLS` section:

```
TLS__Enabled=true
TLS__Listeners__0=0.0.0.0:853
TLS__CertificatePath=/tls/tls.crt
TLS__PrivateKeyPath=/tls/tls.key
TLS__HttpsPort=443
```

When TLS is enabled and `DNS:DesignatedResolvers` is empty, `_dns.resolver.arpa`
is filled from the certificate hostname.

## Container and Helm

Images: `harbor.instigaterevolution.com/instigaterevolution/dhcpr/dns`.
Chart: `charts/dhcpr` — [docs/helm.md](docs/helm.md).
Versioning is [Nerdbank.GitVersioning](https://github.com/dotnet/Nerdbank.GitVersioning)
(`version.json`).

```bash
docker build -t dhcpr .
helm install dhcpr charts/dhcpr
```

Turn on process-terminated DoT/DoH with `secureDns.enabled` (requires
`certManager.dnsNames` or `existingSecret`). HTTP 8080 stays for probes;
`DOTNET_URLS` adds `https://+:443` when TLS is on.

## Benchmark (2026-10-22)

`dnsperf` 2.15.0 on holopoint. Eighty repeated A/AAAA names, all cache hits.
Client flags: `-T 8 -c 200 -q 2000 -e -b 4096`. Every run filled that
2,000-query window (`qps × latency ≈ 2000`), so a higher rate is a lower
latency.

UDP to the public VIP is rate-limited per client, so those runs are left out.
Loopback UDP was rate-limited too. The localhost numbers are TCP.

### CPUs

| Machine | Role | CPU |
|---|---|---|
| holopoint | dnsperf client, and the localhost server | AMD Ryzen 9 7950X, 16 cores / 32 threads |
| kube-worker-phys-8 | node that held the saturated pod | AMD Ryzen 5 PRO 5650GE, 6 cores / 12 threads |

The other two replicas run on `kube-worker-phys-4` and `kube-worker-phys-9`.
Their CPUs were not read. On phys-8, a limit of `6000m` is 6 of the 12
hardware threads.

### Localhost

`Dhcpr.Server` on holopoint, TCP `127.0.0.1:65353`, 30 seconds. CPU is a
`ps` sample mid-run.

| Completed qps | Latency | Lost | Server CPU | Notes |
|---|---|---|---|---|
| 128,553 | 15.4 ms | 0 | 686% | |
| **180,711** | 10.7 ms | 171 | 1032% | Best. Second 10 s was 192,244 qps |
| 132,869 | 14.7 ms | 95 | 787% | JIT and thread-pool settings enabled |
| 136,373 | 14.4 ms | 38 | 702% | Same settings |
| 164,164 | 11.8 ms | 171 | 977% | Those settings removed |
| 175,486 | 11.2 ms | 0 | 1301% | Second 10 s was 183,755 qps |

One run was killed mid-test by a bug and is not a result: 36,680 qps,
2.49% SERVFAIL, then the process was gone.

### dns.alertr.info

Public VIP `23.162.92.54`. The pod that hit the limit was on
kube-worker-phys-8 (5650GE). Pod CPU is `kubectl top` for that pod.
Metrics-server lagged on the two 30-second runs marked as such. The other
samples moved during the run.

`DNS__DNSSEC__Enabled=false` in the HelmRelease is only the default. DNSSEC
was on, via the UI, for every remote run except the last.

| Test | Image | Limit | Completed qps | Latency | Pod CPU | Notes |
|---|---|---|---|---|---|---|
| DoT 60 s | pre-2.0.232 | 4000m | 22,105 | 90 ms | 4000m | Other replicas under 1100m |
| DoT 300 s | pre-2.0.232 | 4000m | 18,479 | — | 4000m | First 3 min ~22k; last minute 14,288. Memory to 2321Mi |
| DoT 30 s | v2.0.232-alpha | 4000m | 25,974 | 75 ms | 3995m | Others 2341m and 1682m. Second 10 s was 27,024 |
| DoT 30 s | v2.0.243-alpha | 4000m | 33,748 | 58 ms | sample lagged | Second 10 s was 34,107 |
| DoT 30 s | v2.0.243-alpha | 6000m | 48,666 | 41 ms | sample lagged | Second 10 s was 50,459 |
| DoT 60 s | v2.0.243-alpha | 6000m | 50,397 | 40 ms | 5945m | Slices 49,974 / 51,776 / 51,151. Memory to 2073Mi |
| TCP 60 s | v2.0.243-alpha | 6000m | **54,689** | 37 ms | 5944m | Best sustained remote rate. Slices 52,880 / 53,851 / 56,587 |
| TCP 120 s, DNSSEC on | v2.0.243-alpha | 6000m | 45,308 | 44 ms | 5947m | 0–90 s was 55,541 / 57,110 / 54,609, then ~14,200. Memory 2406 → 3200Mi |
| TCP 120 s, DNSSEC off | v2.0.243-alpha | 6000m | 53,682 | 37 ms | 5969m | Held: 49,093 / 56,457 / 54,955 / ~54,200. Memory 450 → 2565Mi. 704 lost (0.01%) |

After the 120-second DNSSEC-on run, the hot pod's memory returned to about
265Mi once the load stopped. During the steady portion it had stayed near
2.4Gi.

## License

[GNU Affero General Public License v3.0](LICENSE)
