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
    - backendRefs:
        - name: {{ $fullName }}
          port: {{ .Values.service.httpPort }}
{{- end }}
