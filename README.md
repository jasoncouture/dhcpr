# dhcpr

**Official source: [git.alertr.info/jasoncouture/dhcpr](https://git.alertr.info/jasoncouture/dhcpr).**
GitHub is a read-only mirror. Issues, PRs, and CI belong on git.alertr.info.

Recursive DNS resolver (and optional DHCP server) with a small operator UI.
.NET 10, in-process DoT/DoH, validating DNSSEC, and a Helm chart for Kubernetes.

## What it does

- Classic DNS on UDP/TCP 53
- DNS-over-TLS (RFC 7858) on 853 and DNS-over-HTTPS (RFC 8484) on `/dns-query`
- DDR: SVCB at `_dns.resolver.arpa` advertises DoT (`alpn=dot`) and DoH (`alpn=h2`)
- Validating recursive DNSSEC
- Conditional forwarders (`DNS:Routes`), overlay records, blackhole suffixes, RFC 2136 DynDNS
- Blazor UI (live queries, settings) and Prometheus `/metrics`
- Optional DHCP (off by default)

## Build and run

Requires the .NET 10 SDK.

```bash
dotnet test
dotnet run --project src/Dhcpr.Server
```

Development listens on `http://localhost:5187` (UI) and DNS `127.0.0.1:65353` /
`[::1]:65353`. Production images listen on `8080` (HTTP probes/UI), `53`, `443`,
and `853`.

Configuration is standard ASP.NET Core (`appsettings.json`, environment
variables). DNS bind addresses are `DNS:ListenAddresses` (`udp://`, `tcp://`,
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
Chart: `charts/dhcpr`. Versioning is [Nerdbank.GitVersioning](https://github.com/dotnet/Nerdbank.GitVersioning)
(`version.json`).

```bash
docker build -t dhcpr .
helm install dhcpr charts/dhcpr
```

Turn on process-terminated DoT/DoH with `secureDns.enabled` (requires
`certManager.dnsNames` or `existingSecret`). HTTP 8080 stays for probes;
`DOTNET_URLS` adds `https://+:443` when TLS is on.

## License

[GNU Affero General Public License v3.0](LICENSE)
