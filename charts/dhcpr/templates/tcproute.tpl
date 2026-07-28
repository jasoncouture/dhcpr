{{- if .Values.tcpRoute.enabled }}
{{- $fullName := include "dhcpr.fullname" . -}}
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TCPRoute
metadata:
  name: {{ $fullName }}-dns
  labels:
    {{- include "dhcpr.labels" . | nindent 4 }}
  {{- with .Values.tcpRoute.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
spec:
  parentRefs:
    {{- if .Values.gateway.enabled }}
    - name: {{ $fullName }}
      sectionName: dns-tcp
    {{- else }}
    {{- toYaml .Values.tcpRoute.parentRefs | nindent 4 }}
    {{- end }}
  rules:
    - backendRefs:
        - name: {{ $fullName }}
          port: {{ .Values.service.dnsPort }}
{{- end }}
