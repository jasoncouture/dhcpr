# Operator UI

Blazor Server app. DNS, DoH, DynDNS, `/health`, and `/metrics` never require
login. The DoH hostname does **not** serve this UI — those requests 404
except `/dns-query`. Use a different `Host` (or HTTP 8080).

`Authentication:Enabled` defaults to **false**. The UI is then open (live
queries, settings, Orleans). Sign-in routes are not registered.

## Login

When `Authentication:Enabled` is true, OpenID Connect against
`Authentication:Keycloak` (standard ASP.NET Core `OpenIdConnectOptions`:
Authority, ClientId, scopes, …). Every Razor page then requires a signed-in
user.

| Path | Action |
|------|--------|
| `/account/login` | Challenge (OIDC) |
| `/account/logout` | Sign out cookie + IdP |
| `/Account/AccessDenied` | Authenticated but missing role |

Roles come from the token **`groups`** claim
(`TokenValidationParameters:RoleClaimType`). Pushed Authorization Requests
are disabled (some proxies 502 PAR).

| Role | Can do |
|------|--------|
| `dns-user` | Live queries (`/`) |
| `dns-admin` | Everything `dns-user` can, plus settings and `/orleans` |

A user with only `dns-user` does not see the settings nav.

Behind a reverse proxy, forwarded headers are trusted for RFC 1918, loopback,
and ULA (`10/8`, `172.16/12`, `192.168/16`, `127/8`, `::1`, `fc00::/7`).

Blazor circuits need **sticky sessions** if you run more than one replica
(Helm `httpRoute.sticky` is a Traefik cookie). Data Protection keys live under
`{DataPath}/dataprotection-keys/` — share that volume or logins break across
pods.

## Live queries (`/`)

Last **250** queries, newest first, pushed over the Blazor circuit. A
process-wide ring plus Orleans pub/sub so replicas see each other's traffic.

| Column | Meaning |
|--------|---------|
| Time | Local clock, `HH:mm:ss.fff` |
| Cache | `HIT` or `MISS` |
| Server | Local socket the query arrived on |
| Client | Remote socket |
| Type | QTYPE |
| Name | QNAME |
| RCODE | Response code (`NoError`, `NxDomain`, `ServFail`, …) |
| Via | Middleware that produced the answer (`Blackhole`, `resolver.arpa`, …) |
| Answers | Short text of the RRset |

Controls:

- **Pause** — stop re-rendering; events still buffer, so unpausing catches up
- **Hide blackhole** — drop rows whose Via is `Blackhole`

Health-check probes use `127.0.0.1:0` / `[::1]:0` and are **omitted**. Real
loopback clients (ephemeral source port) are shown, so `dig @127.0.0.1` appears
on a local UI.

Non-`NoError` rows are highlighted.

## Settings (`/settings/…`)

Admin only. Save writes `{DataPath}/settings.json` (atomic replace) and
hot-reloads. The file is watched; an edit on disk is picked up without a
restart.

If `settings.json` is missing, the first start **seeds** it from
appsettings/environment. After that, the file wins for these keys even if you
change appsettings — edit the file or the UI, not both casually.

| Page | Keys |
|------|------|
| `/settings/routes` | `DNS:Routes` |
| `/settings/records` | `DNS:Records` |
| `/settings/blackhole` | `DNS:BlackholeDomains` |
| `/settings/dnssec` | `DNS:Dnssec` |
| `/settings/health` | `DNS:HealthCheck` |
| `/settings/dynamic-dns` | `DynamicDns` |

Not in the UI (restart + env/appsettings only):

- `DNS:ListenAddresses`
- `TLS:*`
- `DNS:DesignatedResolvers`
- `DNS:RootServers`
- `DNS:TrustAnchors`
- `Dhcp:*`
- `DataPath`
- `Authentication:*`

Invalid saves are rejected with a form error; the previous file is left in
place.

## Orleans dashboard (`/orleans`)

Admin only. Cluster membership, grains, and counters. Orleans silo ports
**11111** and **30000** are on the pod (not on the public Service). Live-query
and cache events use Orleans so multiple replicas stay in sync.

## Version

The footer shows the assembly **informational version** (Nerdbank.GitVersioning
in CI, or the Docker `INFORMATIONAL_VERSION` build-arg).
