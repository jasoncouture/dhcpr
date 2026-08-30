{{- $secureDns := index .Values "secure-dns" -}}
{{- if and $secureDns.enabled $secureDns.certManager.enabled (not $secureDns.existingSecret) }}
{{- $fullName := include "dhcpr.fullname" . -}}
{{- $issuer := $secureDns.certManager.issuerRef.name | required "secure-dns.certManager.issuerRef.name is required when cert-manager is enabled" -}}
{{- $dnsNames := $secureDns.certManager.dnsNames -}}
{{- if or (not $dnsNames) (not (index $dnsNames 0)) }}
{{- fail "secure-dns.certManager.dnsNames is required when secure-dns is enabled" }}
{{- end }}
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: {{ $fullName }}-secure-dns
  labels:
    {{- include "dhcpr.labels" . | nindent 4 }}
spec:
  secretName: {{ include "dhcpr.secureDnsSecretName" . }}
  issuerRef:
    name: {{ $issuer }}
    kind: {{ $secureDns.certManager.issuerRef.kind | default "ClusterIssuer" }}
    group: {{ $secureDns.certManager.issuerRef.group | default "cert-manager.io" }}
  dnsNames:
    {{- toYaml $dnsNames | nindent 4 }}
{{- end }}
