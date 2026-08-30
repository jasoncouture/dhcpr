{{- if and .Values.dot.enabled .Values.dot.certManager.enabled (not .Values.dot.existingSecret) }}
{{- $fullName := include "dhcpr.fullname" . -}}
{{- $issuer := .Values.dot.certManager.issuerRef.name | required "dot.certManager.issuerRef.name is required when cert-manager is enabled" -}}
{{- $dnsNames := .Values.dot.certManager.dnsNames -}}
{{- if or (not $dnsNames) (not (index $dnsNames 0)) }}
{{- fail "dot.certManager.dnsNames is required when DoT is enabled" }}
{{- end }}
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: {{ $fullName }}-dot
  labels:
    {{- include "dhcpr.labels" . | nindent 4 }}
spec:
  secretName: {{ include "dhcpr.dotSecretName" . }}
  issuerRef:
    name: {{ $issuer }}
    kind: {{ .Values.dot.certManager.issuerRef.kind | default "ClusterIssuer" }}
    group: {{ .Values.dot.certManager.issuerRef.group | default "cert-manager.io" }}
  dnsNames:
    {{- toYaml $dnsNames | nindent 4 }}
{{- end }}
