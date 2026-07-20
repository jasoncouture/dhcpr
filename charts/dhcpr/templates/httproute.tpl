{{- if .Values.httpRoute.enabled }}
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: {{ include "dhcpr.fullname" . }}
  labels:
    {{- include "dhcpr.labels" . | nindent 4 }}
  {{- with .Values.httpRoute.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
spec:
  parentRefs:
    {{- toYaml .Values.httpRoute.parentRefs | nindent 4 }}
  hostnames:
    - {{ .Values.httpRoute.host }}
  rules:
    - backendRefs:
        - name: {{ include "dhcpr.fullname" . }}
          port: {{ .Values.service.httpPort }}
{{- end }}
