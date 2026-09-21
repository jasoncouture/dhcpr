# dhcpr documentation

**Official source: [git.alertr.info/jasoncouture/dhcpr](https://git.alertr.info/jasoncouture/dhcpr).**
GitHub is a read-only mirror.

dhcpr is a recursive DNS resolver (and optional DHCP server) with an operator UI.
It terminates DNS-over-TLS and DNS-over-HTTPS in-process, validates DNSSEC, and
ships a Helm chart.

| Doc | What it covers |
|-----|----------------|
| [Public resolver](public-resolver.md) | `dns.alertr.info` (`23.162.92.54` / `2602:81e:9004::4`) |
| [Quickstart](quickstart.md) | Clone, build, query, open the UI |
| [Configuration](configuration.md) | Every settings key and environment variable |
| [DNS](dns.md) | How a query is answered |
| [Encrypted DNS](encrypted-dns.md) | DoT, DoH, DDR (`_dns.resolver.arpa`) |
| [UI](ui.md) | Live queries, settings pages, roles |
| [Dynamic DNS](dyndns.md) | HTTP update API (`/nic/update`) |
| [DHCP](dhcp.md) | Optional DHCP server |
| [Helm](helm.md) | Kubernetes chart, ports, `secureDns` |
| [Operations](operations.md) | Health, metrics, OTLP, data directory, versions |

License: [AGPL-3.0](../LICENSE).
