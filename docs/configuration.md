# Configuration

ASP.NET Core configuration: `appsettings.json`, `appsettings.{Environment}.json`,
then environment variables. Nested keys use `__` in the environment
(`DNS__ListenAddresses__0`).

The process **fails to start** if validation fails (`ValidateOnStart` for `DNS`,
`TLS`, `DataPath`, and `Orleans`).

Runtime edits from the UI (routes, records, blackhole, DNSSEC knobs, health
check, DynDNS) are written to `{DataPath}/settings.json` and override the
file/env values for those keys. Listen addresses, TLS, root servers, and trust
anchors are **not** UI-editable.

## `DataPath`

| Key | Default | Purpose |
|-----|---------|---------|
| `DataPath` | `.` (repo `./data` in the sample appsettings; `/data` in the image) | Root for all on-disk state |

Under that directory:

| Path | Contents |
|------|----------|
| `settings.json` | UI-saved settings |
| `dynamic-dns.json` | DynDNS host → address map |
| `dataprotection-keys/` | Unused. Cookie keys are an Orleans grain plus a silo-local push cache |
| `cache/` | `root.zone`, `root-servers.txt` |
| `zones/` | Authoritative zone files |

Use a persistent volume in Kubernetes (`persistence` on the chart). Multiple
replicas need `ReadWriteMany` if they share the same volume.

## `DNS`

Bound as `DNS`. Required: `ListenAddresses` non-empty and valid.

### Listen addresses

```json
"ListenAddresses": [
  "udp://127.0.0.1:65353",
  "tcp://127.0.0.1:65353",
  "interface://eth0:53/"
]
```

| Scheme | Meaning |
|--------|---------|
| `udp://host:port` | UDP only, one address |
| `tcp://host:port` | TCP only, one address |
| `interface://name:port/` | All unicast IPs on that NIC, UDP and TCP |

Default port is 53 when omitted. Host may be a name, IPv4, or `[IPv6]`.
`tls://` is rejected.

### Routes (conditional forwarders)

`DNS:Routes` is a map: **suffix → upstreams**. Longest suffix of the QNAME
wins. The key `"."` is a catch-all after every suffix miss. Names that match
no route go to the recursive resolver (root hints). A loaded `{DataPath}/zones`
file for that name **skips** the forwarder.

```json
"Routes": {
  "home.arpa": {
    "Upstreams": [ "192.168.1.1:53" ],
    "Clients": [ "10.0.0.0/8", "192.168.0.0/16" ]
  }
}
```

| Field | Rule |
|-------|------|
| `Upstreams` | Required, non-empty. `host:port` (port defaults to 53) |
| `Clients` | CIDR or single IP. Empty = any client may use the route |

A client outside `Clients` skips that route and continues (recursion or another
suffix).

### Overlay records

`DNS:Records` — sparse A / AAAA / CNAME / NS. Misses fall through to DynDNS,
zones, then forward/recurse.

| Field | Rule |
|-------|------|
| `Name` | Owner. Leftmost `*` is an RFC 4592 wildcard (`*.apps.home.arpa`) |
| `Type` | `A`, `AAAA`, `CNAME`, `NS` |
| `Ttl` | Seconds. Empty/null → 300 |
| `Value` | IPv4, IPv6, or a domain (CNAME/NS) |
| `Clients` | CIDR/IP allow-list. Empty = any client |

CNAME cannot share the same owner **and** the same `Clients` set with another
type.

### Blackhole

`DNS:BlackholeDomains` — suffixes that always get **NXDOMAIN** (no cache, no
upstream). The name itself and every subdomain match (`example.com` also
matches `www.example.com`).

### Rate limit

`DNS:UdpRateLimit` — sliding window for classic DNS (UDP and TCP). DoT,
DoH, and internal hops are not limited. The section name is historical.

| Key | Default | Meaning |
|-----|---------|---------|
| `Enabled` | `true` | When false, every query is answered |
| `RefuseLimit` | `30` | Queries per window that still get a real answer |
| `DropLimit` | `60` | Queries per window that still get REFUSED. Above this: no reply |
| `WindowMilliseconds` | `1000` | Sliding window length (100–60000) |
| `SegmentsPerWindow` | `10` | Buckets in the window (2–100). More = smoother |

Two windows: client+QNAME+QTYPE at these limits over `WindowMilliseconds`,
and client IP (IPv4 or IPv6 `/64`) over a window **5×** as long at the
same rate as `RefuseLimit` (30/s, 150 per 5 s). At or above that rate the IP gets no
reply. The harsher action wins. Loopback is exempt.

### DNSSEC

`DNS:Dnssec`:

| Key | Default | Meaning |
|-----|---------|---------|
| `Enabled` | `true` | When false: never set AD, never SERVFAIL for Bogus |
| `AllowedAlgorithms` | empty = 8, 13, 14, 15, 16 | Algorithms used for verification |
| `DeniedAlgorithms` | empty | Always rejected, even if also allowed |

Algorithm numbers: RSASHA256 = 8, ECDSAP256SHA256 = 13, ECDSAP384SHA384 = 14,
ED25519 = 15, ED448 = 16. `0` is invalid.

Client behavior when enabled:

- Secure + client asked for AD → `AD=1`
- Bogus and `CD=0` → `SERVFAIL`
- Insecure / Unchecked → no AD

### Trust anchors

`DNS:TrustAnchors` — DS records. The built-in default is the current root KSK
(key tag 20326, algorithm 8, digest type 2). Override only if you know why.

```json
"TrustAnchors": [
  {
    "Name": ".",
    "KeyTag": 20326,
    "Algorithm": 8,
    "DigestType": 2,
    "DigestHex": "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
  }
]
```

### Root servers

`DNS:RootServers` — only **`Addresses`** is used at runtime. `Enabled`,
`Download`, `LoadFromSystem`, and `DownloadUrls` are bound and validated but
the bootstrap/refresh services do not read them. The image’s
`DNS__ROOTSERVERS__DOWNLOAD=true` is therefore a no-op.

| Key | Default in code | What actually happens |
|-----|-----------------|------------------------|
| `Addresses` | empty | If non-empty, these IPs (optional `:port`, default 53) **are** the root tips. No `named.root` fetch. |
| `Enabled` / `Download` / `LoadFromSystem` / `DownloadUrls` | `true` / `true` / `true` / Internic URIs | Validated only |

When `Addresses` is empty:

1. Load `{DataPath}/cache/root-servers.txt` if present
2. Else fetch `named.root` from hardcoded Internic / `192.0.46.9` URLs and cache the IPs
3. `root.zone` is always pulled from `https://www.internic.net/domain/root.zone` on a SOA-based timer (needs outbound HTTPS; InterNIC wants a User-Agent)

Cache files live under `{DataPath}/cache/`.

### Designated resolvers (DDR)

`DNS:DesignatedResolvers` — SVCB answers at `_dns.resolver.arpa`. Empty is
valid: the zone is still served locally (NODATA) and **never forwarded**.

See [encrypted DNS](encrypted-dns.md). Each entry:

| Field | Rule |
|-------|------|
| `Priority` | 1–65535 (ServiceMode; 0 is AliasMode and rejected) |
| `Target` | Hostname. Not `.` and not `resolver.arpa` |
| `Alpn` | e.g. `dot`, `h2` |
| `Port` | Optional 1–65535 |
| `DohPath` | Optional URI template; must start with `/`. Requires `Alpn` |
| `Ipv4Hint` / `Ipv6Hint` | Optional address hints |

### Health check

`DNS:HealthCheck` drives `GET /health`:

| Key | Default | Meaning |
|-----|---------|---------|
| `Enabled` | `true` | When false, the check is always Healthy |
| `Domains` | empty | Hostnames resolved through the **DNS pipeline** (A and AAAA). Empty → Healthy |
| `TimeoutSeconds` | `5` | 1–120, for the whole batch |

Any domain that fails both A and AAAA (no response, bad rcode, no address/CNAME)
makes the process **Unhealthy**. Kubernetes probes hit this path.

### DoH limits

`DNS:DOH` (JSON key `DOH`):

| Key | Default | Meaning |
|-----|---------|---------|
| `MaxRequestBytes` | `65535` | Max POST body or GET-decoded wire size (1–65535) |
| `IsolateHost` | `true` | Advertised DoH hostname 404s every path except `/dns-query`. Set `false` to serve the operator UI on the same name. |

## `TLS`

Separate from `DNS:ListenAddresses`. When `Enabled` is false, listeners and
cert paths are ignored.

| Key | Default | Meaning |
|-----|---------|---------|
| `Enabled` | `false` | Master switch |
| `Listeners` | empty | `IP` or `IP:port` (default port **853**) |
| `CertificatePath` | | PEM cert (required if enabled) |
| `PrivateKeyPath` | | PEM key (required if enabled) |
| `HttpsPort` | `443` | Kestrel HTTPS (DoH). Files need not exist at validation time. When `DNS:DOH:IsolateHost` is true, the advertised DoH hostname 404s every path except `/dns-query`. |

TLS 1.2/1.3, ALPN `dot` advertised on 853. No client certificates. The same PEM
is used for Kestrel HTTPS. Cert files are re-read when mtime changes (no
watcher).

Do **not** put `tls://` on `DNS:ListenAddresses`.

`ListenAnyIP` is not used for HTTPS: that would drop `DOTNET_URLS` (probes on
8080). The chart sets `DOTNET_URLS=http://+:8080;https://+:443` when
`secureDns` is on. See [encrypted DNS](encrypted-dns.md) and [Helm](helm.md).

## `DynamicDns`

Root-level (also editable in the UI). When enabled, username and password are
required.

| Key | Default | Meaning |
|-----|---------|---------|
| `Enabled` | `true` | HTTP update endpoints |
| `Username` / `Password` | | HTTP Basic |
| `TtlSeconds` | `60` | 1–86400 |
| `TrustForwardedFor` | `false` | Use first `X-Forwarded-For` hop when `myip` is omitted |

See [Dynamic DNS](dyndns.md).

## `Dhcp`

| Key | Default | Meaning |
|-----|---------|---------|
| `Enabled` | `false` (image: `DHCP__ENABLED=false`) | Only switch that is honored: bind UDP 67 |
| `Subnets` | empty | Bound but **not used** — lease pool is hardcoded (see [DHCP](dhcp.md)) |

## `Authentication`

OpenID Connect for the operator UI. **Off by default** — the UI is open and
every visitor can use live queries, settings, and `/orleans`. Login routes
are not mapped.

| Key | Default | Meaning |
|-----|---------|---------|
| `Enabled` | `false` | When true, require Keycloak OIDC |
| `Keycloak:Authority` | | Required when enabled (issuer URL) |
| `Keycloak:ClientId` | | Required when enabled |
| `Keycloak:*` | | Other keys bind to `OpenIdConnectOptions` |

When enabled, roles come from the token `groups` claim
(`TokenValidationParameters:RoleClaimType`).

| Role | Access |
|------|--------|
| `dns-user` | Live queries |
| `dns-admin` | Settings, Orleans dashboard |

See [UI](ui.md).

## `Orleans`

Membership. In a Kubernetes pod the process uses kube clustering and ignores
this section. Anywhere else it needs Consul, or a Debug build falls back to
localhost.

| Key | Default | Meaning |
|-----|---------|---------|
| `UseConsul` | `false` | Join Consul when not in-cluster |
| `Consul:Address` | | Required when `UseConsul` is true. `http` or `https` URI |
| `Consul:Token` | | Optional ACL token |
| `Consul:KvRootFolder` | | Optional KV prefix; empty uses the provider default |
| `AdvertisedIP` | first non-loopback address | IP other silos use to reach this process |
| `SiloPort` | `11111` | Silo-to-silo |
| `GatewayPort` | `30000` | Client gateway |

Set `AdvertisedIP` when auto-detect picks the wrong NIC (or there is none).
Silo and gateway listen on all interfaces.

`ClusterId` and `ServiceId` are `dhcpr` (same as the Helm labels).

## Environment cheat sheet

```bash
# DNS
DNS__ListenAddresses__0=udp://0.0.0.0:53
DNS__Routes__home.arpa__Upstreams__0=192.168.1.1:53
DNS__BlackholeDomains__0=ads.example
DNS__Dnssec__Enabled=true
DNS__UdpRateLimit__RefuseLimit=30
DNS__UdpRateLimit__DropLimit=60
DNS__HealthCheck__Domains__0=example.com

# TLS / DoT / DoH
TLS__Enabled=true
TLS__Listeners__0=0.0.0.0:853
TLS__Listeners__1='[::]:853'
TLS__CertificatePath=/tls/tls.crt
TLS__PrivateKeyPath=/tls/tls.key
TLS__HttpsPort=443

# Process
DataPath=/data
DOTNET_URLS=http://+:8080
DHCP__ENABLED=false

# OIDC (off unless Enabled=true)
Authentication__Enabled=true
Authentication__Keycloak__Authority=https://auth.alertr.info/realms/master
Authentication__Keycloak__ClientId=dhcpr

# Consul (outside Kubernetes)
Orleans__UseConsul=true
Orleans__Consul__Address=http://consul:8500
Orleans__AdvertisedIP=10.0.0.8
```

OpenTelemetry is the SDK’s `OTEL_*` variables. No `appsettings` section.
See [operations](operations.md#tracing-and-otlp).
