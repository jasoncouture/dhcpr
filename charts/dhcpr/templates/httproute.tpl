{{- if .Values.httpRoute.enabled }}
{{- $fullName := include "dhcpr.fullname" . -}}
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: {{ $fullName }}
  labels:
    {{- include "dhcpr.labels" . | nindent 4 }}
  {{- with .Values.httpRoute.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
spec:
  parentRefs:
    {{- if .Values.gateway.enabled }}
    - name: {{ $fullName }}
      sectionName: websecure
    {{- else }}
    {{- toYaml .Values.httpRoute.parentRefs | nindent 4 }}
    {{- end }}
  hostnames:
    - {{ .Values.httpRoute.host | quote }}
  rules:
    # Serves Prometheus /metrics and RFC 8484 DNS-over-HTTP at /dns-query (plain HTTP to the pod;
    # TLS terminates on the Gateway). Blazor Interactive Server needs sticky sessions across
    # replicas — when sticky.enabled, backend is a TraefikService with cookie affinity.
    - matches:
        - path:
            type: PathPrefix
            value: /
      backendRefs:
        {{- if .Values.httpRoute.sticky.enabled }}
        - group: traefik.io
          kind: TraefikService
          name: {{ printf "%s-sticky" $fullName }}
        {{- else }}
        - name: {{ $fullName }}
          port: {{ .Values.service.httpPort }}
        {{- end }}
{{- end }}
