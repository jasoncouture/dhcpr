# Helm

Chart path: [`charts/dhcpr`](../charts/dhcpr). Chart version and `appVersion`
start at **2.0.0**; CI replaces `appVersion` with the image tag from
Nerdbank.GitVersioning.

```bash
helm install dhcpr charts/dhcpr
```

Image default: `harbor.instigaterevolution.com/instigaterevolution/dhcpr/dns`.
Override `image.tag` if you are not using the chart `appVersion`.

## What you get

| Object | Purpose |
|--------|---------|
| Deployment | One container: HTTP 8080, DNS 53/udp+tcp, optional 443 + 853, Orleans 11111/30000 |
| Service | ClusterIP: `http`, `dns-udp`, `dns-tcp`; plus `https` / `dns-tls` when `secureDns.enabled` |
| PVC | `{fullname}-data` mounted at `/data` (`DataPath`) |
| ServiceAccount | Named after the release |
| ServiceMonitor | Optional Prometheus Operator scrape of `/metrics` on `http` |
| Certificate | cert-manager, only if `secureDns` + cert-manager and no `existingSecret` |
| Gateway / HTTPRoute / TCPRoute / UDPRoute | Off by default |

Rollout default: `RollingUpdate`, `maxUnavailable: 0`, `maxSurge: 3`.

## Required DNS bind env

`appsettings.Production.json` already binds `0.0.0.0` / `[::]:53`. The chart
repeats that in `env` so a Development-based image or a loopback override
cannot hide the Service:

```yaml
env:
  - name: DNS__ListenAddresses__0
    value: "udp://0.0.0.0:53"
  - name: DNS__ListenAddresses__1
    value: "tcp://0.0.0.0:53"
  - name: DNS__ListenAddresses__2
    value: "udp://[::]:53"
  - name: DNS__ListenAddresses__3
    value: "tcp://[::]:53"
```

Add more with `env` / `envFrom`. Do not add `tls://` here.

## Persistence

`persistence.size` (default 1Gi), `storageClassName`, `accessMode`
(default **ReadWriteMany**). Use RWX if `replicaCount > 1` so
`settings.json`, zones, DynDNS, and cache are shared. Cookie keys are an
Orleans grain plus a silo-local push cache, not the PVC.

## Probes

Liveness and readiness: `GET /health` on port **`http` (8080)**. That check
resolves `DNS:HealthCheck:Domains` through the DNS pipeline. Empty domain list
or `Enabled: false` → Healthy. See [operations](operations.md).

Never point probes at 443; 8080 is always HTTP.

## `authentication` (OIDC)

Off by default. The operator UI is then reachable without login. When
`enabled` is true, `authority` and `clientId` are required; the chart sets
`Authentication__Enabled` and `Authentication__Keycloak__*`.

To restore the current Keycloak client (`dhcpr` on `auth.alertr.info`):

```yaml
authentication:
  enabled: true
  authority: https://auth.alertr.info/realms/master
  clientId: dhcpr
  responseType: code
  usePkce: true
  saveTokens: true
  roleClaimType: groups
  scopes:
    - openid
    - profile
    - email
    - roles
```

## `secureDns` (DoT + DoH)

Process-terminated TLS. **No Gateway listener** for 853/443 — the Service
gains those ports and you front them with whatever LoadBalancer you own
(often a separate Flux object, not this chart).

```yaml
secureDns:
  enabled: true
  dotPort: 853
  dohPort: 443
  existingSecret: ""          # tls.crt / tls.key in a kubernetes.io/tls secret
  certManager:
    enabled: true
    issuerRef:
      name: your-dns01-issuer
      kind: ClusterIssuer
    dnsNames:
      - dns.example.com       # required, at least one
```

Rules:

- `enabled` requires **`existingSecret` or `certManager.enabled`**
- `certManager.dnsNames` must be non-empty whenever `secureDns` is on
  (used for the Certificate **and** for DDR env)
- Certificate object is created only when cert-manager is on **and**
  `existingSecret` is empty
- Secret is mounted at `/tls` (`tls.crt`, `tls.key`)

The Deployment then sets:

```
DOTNET_URLS=http://+:8080;https://+:443
TLS__Enabled=true
TLS__Listeners__0=0.0.0.0:853
TLS__Listeners__1=[::]:853
TLS__CertificatePath=/tls/tls.crt
TLS__PrivateKeyPath=/tls/tls.key
TLS__HttpsPort=443
DNS__DesignatedResolvers__0  → DoT  (alpn=dot, first dnsName)
DNS__DesignatedResolvers__1  → DoH  (alpn=h2, dohpath=/dns-query{?dns})
```

`dnsNames[0]` is the advertised hostname. Put the name clients will use first.

## Gateway API (optional)

`gateway.enabled` creates an in-namespace Gateway (default class `traefik`).
`httpRoute` attaches to `websecure` and can create a TraefikService cookie for
Blazor stickiness. `tcpRoute` / `udpRoute` attach classic DNS to the Gateway
`dns-tcp` / `dns-udp` listeners.

HTTPRoute is for the **UI** (and can reach `/dns-query` on the pod’s HTTP
port). DoT/DoH on 853/443 are `secureDns`, not these routes.

## ServiceMonitor

```yaml
serviceMonitor:
  enabled: true
  path: /metrics
  interval: 30s
  labels:
    release: monitoring-kube-prometheus-stack
```

`release` must match your kube-prometheus-stack `serviceMonitorSelector`.

## Orleans

Pods are labeled `orleans/serviceId=dhcpr` and `orleans/clusterId=dhcpr`.
Silo and gateway ports are on the pod spec only. In-cluster the process uses
kube membership. Outside the cluster, set `Orleans:UseConsul` — see
[configuration](configuration.md#orleans). Dashboard: `/orleans` (admin role).

## Public VIP

This chart’s Service is ClusterIP. The published instance
[dns.alertr.info](public-resolver.md) is a separate LoadBalancer
(`23.162.92.54` / `2602:81e:9004::4`) in front of `https`, `dns-tls`, and
classic 53. That object is not in this repository.
