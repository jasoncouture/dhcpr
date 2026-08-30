# Encrypted DNS

dhcpr terminates **DNS-over-TLS** (RFC 7858) and **DNS-over-HTTPS** (RFC 8484)
in-process. Classic UDP/TCP stays on `DNS:ListenAddresses`. There is no `tls://`
listen scheme.

## TLS section

| Key | Meaning |
|-----|---------|
| `TLS:Enabled` | Master switch. When false, everything below is ignored |
| `TLS:Listeners` | `IP` or `IP:port` (default port **853**) |
| `TLS:CertificatePath` | PEM certificate |
| `TLS:PrivateKeyPath` | PEM private key |
| `TLS:HttpsPort` | Kestrel HTTPS port for DoH and the UI (default 443) |

Same certificate for DoT and HTTPS. Files are re-read when mtime changes.
TLS 1.2 and 1.3; ALPN `dot` is advertised on 853. No client certificates.

Validation requires the PEM paths when enabled. The files do not have to exist
at process start (cert-manager may still be issuing). If they cannot be loaded
later, DoT accept fails and DDR auto-advertisement is skipped.

### Do not steal port 8080

Kestrel must **not** call `ListenAnyIP` for HTTPS. That replaces `DOTNET_URLS`
and drops the HTTP probe port.

- Image default: `DOTNET_URLS=http://+:8080`
- With TLS (Helm `secureDns`): `DOTNET_URLS=http://+:8080;https://+:443`

Probes and `/metrics` stay on **8080**. Clients use **443** for DoH/UI (or
whatever `HttpsPort` / `secureDns.dohPort` is).

## DNS-over-TLS (853)

Bind listeners, enable TLS, point at PEM files:

```bash
TLS__Enabled=true
TLS__Listeners__0=0.0.0.0:853
TLS__Listeners__1='[::]:853'
TLS__CertificatePath=/tls/tls.crt
TLS__PrivateKeyPath=/tls/tls.key
```

Query (Knot `kdig`):

```bash
kdig @dns.example.com +tls-ca +tls-host=dns.example.com example.com A
```

Or `dig` with a TLS-capable build:

```bash
dig @dns.example.com +tls example.com A
```

On Android / Unbound / systemd-resolved, set the hostname to a name that is on
the certificate (SAN or CN).

## DNS-over-HTTPS (`/dns-query`)

RFC 8484 on Kestrel HTTPS (and also on plain HTTP 8080 if you call it there).

| Method | Rules |
|--------|--------|
| `POST /dns-query` | `Content-Type: application/dns-message`, body = wire bytes |
| `GET /dns-query?dns=` | `dns` is **base64url** of the wire query |

Responses are `application/dns-message`.

Limits: `DNS:DOH:MaxRequestBytes` (default 65535). Oversize → **413**.
Wrong content type on POST → **415**. Missing/invalid `dns=` → **400**.
Executor produced no answer → **503**. Client abort → **499**.

No login. Do not expose 8080 to the internet if you only wanted DoH on 443.

Example GET (after encoding a query with `dnstools` or similar):

```bash
curl -sS 'https://dns.example.com/dns-query?dns=<base64url>' \
  -H 'Accept: application/dns-message' -o answer.bin
```

## Discovery of Designated Resolvers (RFC 9462)

`resolver.arpa` is **always** answered locally. It is never forwarded to the
public DNS and never cached.

A `SVCB` query for **`_dns.resolver.arpa`** returns the designated resolvers.
Anything else under `resolver.arpa` is NODATA (NOERROR, empty answer).

### Who gets advertised

1. If `DNS:DesignatedResolvers` is non-empty, that list is used as-is.
2. Else if `TLS:Enabled` and the cert loads, synthesize:
   - priority 1, `alpn=dot`, port from the first TLS listener (or 853)
   - priority 2, `alpn=h2`, `port` = `HttpsPort`, `dohpath=/dns-query{?dns}`
   - target = first **non-wildcard** SAN, else CN
3. Else NODATA.

Cert load errors (`IOException`, `CryptographicException`) → no auto list.

Helm, when `secureDns.enabled`, injects explicit
`DNS__DesignatedResolvers__0/1` from the **first**
`secureDns.certManager.dnsNames` entry (same shape as the auto list). That
wins over cert introspection.

### Check it

```bash
dig @<resolver> _dns.resolver.arpa SVCB +norecurse
```

You should see two ServiceMode records (priorities 1 and 2) when TLS is up.
Clients that implement DDR (recent Android, some stubs) will prefer DoT/DoH
automatically.

## Helm

See [Helm](helm.md) `secureDns`. Public MetalLB / extra LoadBalancer objects
are **not** in this repo; this chart only exposes ClusterIP ports `dns-tls`
and `https` when `secureDns` is on.
