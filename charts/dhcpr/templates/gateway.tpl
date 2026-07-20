{{- if .Values.gateway.enabled }}
{{- $fullName := include "dhcpr.fullname" . -}}
{{- $hostname := .Values.gateway.hostname | default .Values.httpRoute.host -}}
# Self-contained Gateway in this release's namespace — Traefik watches every
# Gateway with gatewayClassName: traefik and merges onto its existing
# dataplane/LB (no per-Gateway infrastructure, no cross-namespace ReferenceGrant).
# cert-manager gateway-shim issues the Certificate into this same namespace.
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: {{ $fullName }}
  labels:
    {{- include "dhcpr.labels" . | nindent 4 }}
  {{- with .Values.gateway.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
spec:
  gatewayClassName: {{ .Values.gateway.className }}
  listeners:
    - name: websecure
      port: {{ .Values.gateway.port }}
      protocol: HTTPS
      hostname: {{ $hostname | quote }}
      allowedRoutes:
        namespaces:
          from: Same
      tls:
        mode: Terminate
        certificateRefs:
          - name: {{ .Values.gateway.certificateSecretName | default (printf "%s-tls" $fullName) }}
{{- end }}
