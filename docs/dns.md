# DNS

Classic DNS (UDP/TCP) is configured only under `DNS:ListenAddresses`. Encrypted
transports are [separate](encrypted-dns.md). Every query, including DoH and
health-check probes, goes through the same pipeline.

## How a query is answered

Order (outermost first):

1. **Log** — every answer is recorded for the live-query UI (`Via` column).
2. **Metrics** — increments `dns.queries` (see [operations](operations.md)).
3. **Query class** — only **IN** is forwarded or recursed. Class **CH**:
   BIND identity names get bait TXT (`9.9.4-P2-RedHat-…` / `ns1` /
   `Mark Andrews`); `ip.info` is the client address as TXT; every other
   CH name is local **NXDOMAIN**. HS, CS, QCLASS ANY, and unknown
   classes are **NOTIMP**.
4. **`resolver.arpa`** — served locally, never cached, never forwarded
   ([encrypted DNS](encrypted-dns.md)).
5. **RFC 6303 empty reverse zones** — RFC1918 / link-local / ULA `in-addr.arpa`
   and `ip6.arpa` names are NXDOMAIN locally (no public leak, no DNSSEC
   SERVFAIL). A loaded zone, overlay record, or specific forwarder route still
   wins.
6. **Blackhole** — configured suffixes return **NXDOMAIN**.
7. **Unsupported QTYPE** — `ANY` (255) and other unknown types return **NOTIMP**.
8. **Shuffle** — A/AAAA answer order is rotated per query (including cache hits).
9. **DNSSEC** — validate the assembled answer; may SERVFAIL (see below).
10. **RA** — set Recursion Available on the response.
11. **A/AAAA prefetch** — after an external IN A or AAAA answer, resolve the
    sibling type into cache. Internal and prefetch hops do not prefetch
    (no A ⇄ AAAA loop).
12. **CNAME chase** — follow CNAMEs and assemble the final set.
13. **Cache** — replay a previous answer unless the handler marked it uncacheable.
14. **SERVFAIL retry** — one more pass on some failures.

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
NAPTR, LUA, SOA, DS, RRSIG.

`$GENERATE` and types the parser does not know (DNSKEY, NSEC, and similar)
are stripped so signed InterNIC-style files can still load the useful records.
RRSIGs are parsed from presentation format (RFC 4034 §3.2) and kept.

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
- Signed child with no parent DS (NODATA) → **insecure**, not SERVFAIL

When disabled: never set AD, never SERVFAIL solely because validation failed.

`AllowedAlgorithms` empty means 8, 13, 14, 15, 16
(RSASHA256, ECDSAP256SHA256, ECDSAP384SHA384, ED25519, ED448).
`DeniedAlgorithms` always lose. Algorithm `0` is invalid.

Trust anchors are `DNS:TrustAnchors` (DS records). The compiled default is the
current root KSK (key tag 20326). Override only when you intend to.

## UDP size (amplification)

Classic DNS over UDP is capped at **1232** bytes. Larger answers (TXT, DNSSEC
assemblies, and similar) are returned as **TC** with empty answer / authority /
additional sections. Clients retry over TCP. Client EDNS payload sizes above
1232 are ignored so a spoofed source cannot bounce a multi-kilobyte UDP
response at a victim. A request COOKIE (RFC 7873) is echoed on the reply;
cached or upstream COOKIE bytes are not replayed.

TCP, DoT, and DoH are not capped this way. A TCP/DoT client must send a
complete length-prefixed message within **5 seconds** or the connection is
closed (Slowloris).

## Rate limit

Classic DNS (UDP and TCP) shares two sliding windows (`DNS:UdpRateLimit`).
The harsher action wins. DoT, DoH, and internal pipeline hops are not
limited.

Per **client + QNAME + QTYPE** (1 s / 10 segments):

1. Up to **RefuseLimit** (30) — answered normally
2. Up to **DropLimit** (60) — **REFUSED** (policy reject, no recursion)
3. Above that — **no reply**

Per **client IP** (IPv4 address or IPv6 `/64`), a **5 s** window at the
same rate as RefuseLimit (**30/s**, so 150 queries per 5 s). At or above
that is abuse: **no reply**.

Loopback is not limited. UDP and TCP from the same client share a bucket.

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
