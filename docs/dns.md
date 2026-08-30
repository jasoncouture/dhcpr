# DNS

Classic DNS (UDP/TCP) is configured only under `DNS:ListenAddresses`. Encrypted
transports are [separate](encrypted-dns.md). Every query, including DoH and
health-check probes, goes through the same pipeline.

## How a query is answered

Order (outermost first):

1. **Log** — every answer is recorded for the live-query UI (`Via` column).
2. **Metrics** — increments `dns.queries` (see [operations](operations.md)).
3. **`resolver.arpa`** — served locally, never cached, never forwarded
   ([encrypted DNS](encrypted-dns.md)).
4. **Blackhole** — configured suffixes return **NXDOMAIN**.
5. **Unsupported QTYPE** — `ANY` (255) and other unknown types return **NOTIMP**.
6. **Shuffle** — A/AAAA answer order is rotated per query (including cache hits).
7. **DNSSEC** — validate the assembled answer; may SERVFAIL (see below).
8. **RA** — set Recursion Available on the response.
9. **CNAME chase** — follow CNAMEs and assemble the final set.
10. **Cache** — replay a previous answer unless the handler marked it uncacheable.
11. **SERVFAIL retry** — one more pass on some failures.

Then the inner handlers, first match wins:

| Handler | What it answers |
|---------|-----------------|
| Root zone | Names in the cached `root.zone` (hints / apex) |
| Directed upstream | Query arrived with explicit peer endpoints (internal hops) |
| Configured records | `DNS:Records` overlay |
| Dynamic DNS | Hosts updated via HTTP ([dyndns](dyndns.md)) |
| Authoritative zones | `{DataPath}/zones/**/*.bind` |
| NS cut | Referrals for loaded zones |
| Conditional forwarder | Longest `DNS:Routes` suffix whose `Clients` match |
| Recursive resolver | Walk from root hints |
| SERVFAIL | Nothing else produced an answer |

Configured records, DynDNS, and zone files are **authoritative overlays**. A miss
falls through; a hit does not go to public DNS.

## Conditional forwarders

`DNS:Routes` is a map of **DNS suffix → upstreams**. Longest suffix that matches
the QNAME wins. Key `"."` is a catch-all after every suffix miss. If that route
has `Clients` and the querier is outside those CIDRs, the route is skipped
(another suffix or recursion may still apply). A name that sits in a loaded
`*.bind` zone is **not** forwarded.

```json
"Routes": {
  "lab.example": {
    "Upstreams": [ "10.0.0.53:53" ],
    "Clients": [ "10.0.0.0/8" ]
  }
}
```

Empty `Clients` means any client. Upstream is `host:port` (port defaults to 53).
The default UDP timeout to an upstream is **250 ms**.

## Overlay records

Sparse A / AAAA / CNAME / NS in `DNS:Records`. Leftmost `*` is a wildcard
(`*.apps.home.arpa` matches `foo.apps.home.arpa`, not `apps.home.arpa`).

Default TTL is 300 if omitted. `Clients` works like routes. CNAME cannot share
the same owner **and** the same client set with another type.

These are not a full zone. For SOA, MX, TXT, SRV, and the rest, use a BIND file
(below).

## Authoritative zone files

Drop BIND-style files at `{DataPath}/zones/**/*.bind`. They load on start and
reload ~500 ms after a filesystem change.

Supported record types that are mapped into answers:

A, AAAA, NS, CNAME, DNAME, ALIAS, PTR, MX, TXT, HINFO, SRV, CAA, TLSA, SSHFP,
NAPTR, LUA, SOA, DS.

`$GENERATE` and types the parser does not know (including most DNSSEC RRSIGs)
are stripped so signed InterNIC-style files can still load the useful records.

Example `{DataPath}/zones/home.arpa.bind`:

```
$TTL 300
@   IN SOA ns.home.arpa. hostmaster.home.arpa. (
        1 3600 600 86400 300 )
    IN NS  ns.home.arpa.
ns  IN A   192.168.1.10
app IN A   192.168.1.20
```

The zone apex is inferred from the file. DynDNS updates are allowed only for
names that already sit in a loaded zone (`nohost` otherwise).

## Blackhole

`DNS:BlackholeDomains` — the name and every subdomain return NXDOMAIN with no
cache and no upstream. Useful for ads / malware suffixes. The live-query page
can hide these rows.

## Recursion and cache

If no overlay or route applies, the server walks from root hints
(`DNS:RootServers:Addresses`, or a downloaded `named.root`). `root.zone` is
always fetched from InterNIC and cached under `{DataPath}/cache/` (SOA refresh
timer). The `Download` flag is not read — see [configuration](configuration.md).

Answers are cached in-process (about **100 000** entries, then compaction).
Blackhole, `resolver.arpa`, DynDNS, and some internal hops are not cached.

A/AAAA order is shuffled **after** the cache so clients do not all stick to the
same first address.

## DNSSEC

`DNS:Dnssec.Enabled` defaults to **true**.

When enabled:

- Secure answers with the client AD bit requested → response `AD=1`
- Bogus answers with `CD=0` → **SERVFAIL**
- Insecure / unchecked → no AD bit

When disabled: never set AD, never SERVFAIL solely because validation failed.

`AllowedAlgorithms` empty means 8, 13, 14, 15, 16
(RSASHA256, ECDSAP256SHA256, ECDSAP384SHA384, ED25519, ED448).
`DeniedAlgorithms` always lose. Algorithm `0` is invalid.

Trust anchors are `DNS:TrustAnchors` (DS records). The compiled default is the
current root KSK (key tag 20326). Override only when you intend to.

## Query from a client

The public instance is [dns.alertr.info](public-resolver.md)
(`23.162.92.54` / `2602:81e:9004::4`).

Development (unprivileged port):

```bash
dig @127.0.0.1 -p 65353 example.com A
```

On the LAN / in-cluster (port 53):

```bash
dig @<resolver-ip> example.com A +dnssec
```

`+dnssec` sets DO; you will see AD on Secure answers when validation is on.
