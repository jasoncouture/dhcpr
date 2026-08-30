{{- if and .Values.secureDns.enabled .Values.secureDns.certManager.enabled (not .Values.secureDns.existingSecret) }}
{{- $fullName := include "dhcpr.fullname" . -}}
{{- $issuer := .Values.secureDns.certManager.issuerRef.name | required "secureDns.certManager.issuerRef.name is required when cert-manager is enabled" -}}
{{- $dnsNames := .Values.secureDns.certManager.dnsNames -}}
{{- if or (not $dnsNames) (not (index $dnsNames 0)) }}
{{- fail "secureDns.certManager.dnsNames is required when secureDns is enabled" }}
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
    kind: {{ .Values.secureDns.certManager.issuerRef.kind | default "ClusterIssuer" }}
    group: {{ .Values.secureDns.certManager.issuerRef.group | default "cert-manager.io" }}
  dnsNames:
    {{- toYaml $dnsNames | nindent 4 }}
{{- end }}
