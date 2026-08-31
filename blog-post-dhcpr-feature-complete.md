# dhcpr is feature complete

I have been building a DNS resolver. Today it does the job I set out to do, and that feels better than I expected.

The project is **dhcpr**. Official source is [git.alertr.info/jasoncouture/dhcpr](https://git.alertr.info/jasoncouture/dhcpr). GitHub is a mirror. License is AGPL-3.0.

There is a public instance you can point a stub at right now:

| | |
|---|---|
| Hostname | `dns.alertr.info` |
| IPv4 | `23.162.92.54` |
| IPv6 | `2602:81e:9004::4` |

Classic DNS on 53 (UDP and TCP), DNS-over-TLS on 853, DNS-over-HTTPS on 443 at `/dns-query`. Same certificate on both TLS ports (`CN=dns.alertr.info`).

```bash
dig @dns.alertr.info cloudflare.com A +dnssec
```

You want `ad` in the flags and an RRSIG in the answer.

## What “done” means here

I wanted one process that could sit on a network I care about and be a real resolver, not a forwarder with a web UI glued on.

It recurses from root hints. It validates DNSSEC. It can forward some suffixes to an internal nameserver and recurse everything else. It can answer a handful of overlay records and BIND-style zone files without pretending those are the whole internet. It can sinkhole suffixes. It terminates DoT and DoH itself — no sidecar, no `tls://` listen scheme bolted onto the classic DNS sockets. It advertises those transports with DDR (`SVCB` at `_dns.resolver.arpa`) so a client that speaks RFC 9462 can find them.

The operator UI is a small Blazor app: live queries (who asked, what they asked, cache hit, which middleware answered), plus settings for routes, records, blackhole, DNSSEC knobs, health-check names, and DynDNS. OpenID Connect is optional and off by default. Prometheus is at `/metrics`. Health is `GET /health`, and that check actually runs names through the DNS pipeline.

It runs in Kubernetes. The Helm chart is in the repo. Classic DNS, TLS, and the UI share one container. HTTP 8080 stays up for probes even when HTTPS is on 443; that was a real footgun and it is documented because I stepped on it.

DynDNS is HTTP dyndns2 (`/nic/update`), not RFC 2136 UPDATE. DHCP exists and is off by default. Do not buy it as a Kea replacement.

## Why write another resolver

Because I wanted to own the path from a query on the wire to an answer I could defend.

Encrypted DNS is table stakes now. Doing it in-process means one certificate, one set of listen addresses, and DDR that is not a lie. Validating DNSSEC means the AD bit is *ours* — we do not copy it from upstream. The cache stores RRSIGs and we re-verify. Bogus with `CD=0` is SERVFAIL.

The live-query page is the part I did not know I needed. Watching a resolver work is how you learn whether the pipeline is honest. Health-check probes use port 0 so they do not pollute the table. Real `dig @127.0.0.1` shows up.

I also wanted the docs to match the code. Root-hint download flags that nobody reads are called out. The DHCP pool that is still hardcoded is called out. I would rather a short, accurate page than a feature list that lies.

## Using the public resolver

Pin the addresses if you do not want a chicken-and-egg lookup:

```bash
dig @23.162.92.54 example.com A
dig @2602:81e:9004::4 example.com AAAA
```

DoT (hostname must be `dns.alertr.info`):

```bash
dig @dns.alertr.info +tls example.com A
```

DoH is `https://dns.alertr.info/dns-query` (RFC 8484, `application/dns-message`). Clients that implement DDR can query `_dns.resolver.arpa` `SVCB` and get DoT (`alpn=dot`) and DoH (`alpn=h2`, `dohpath=/dns-query{?dns}`).

The UI on that host is not a public admin panel.

## Running your own

.NET 10 SDK:

```bash
git clone https://git.alertr.info/jasoncouture/dhcpr.git
cd dhcpr
dotnet test
dotnet run --project src/Dhcpr.Server
```

Dev binds the UI on `http://localhost:5187` and DNS on `127.0.0.1:65353` (so you do not need to own port 53). The rest is environment variables and a Helm values file. Operator docs live in [`docs/`](https://git.alertr.info/jasoncouture/dhcpr/src/branch/main/docs).

## What I am not claiming

Feature complete is not “finished forever.” It means the resolver I wanted exists: recurse, validate, encrypt, observe, deploy. The interesting bugs from here are production bugs, not missing protocol checkboxes.

If you run it, query it, or read the code, that is enough. I am glad it is out of the “almost” pile.
