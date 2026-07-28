{{- if .Values.udpRoute.enabled }}
{{- $fullName := include "dhcpr.fullname" . -}}
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: UDPRoute
metadata:
  name: {{ $fullName }}-dns
  labels:
    {{- include "dhcpr.labels" . | nindent 4 }}
  {{- with .Values.udpRoute.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
spec:
  parentRefs:
    {{- if .Values.gateway.enabled }}
    - name: {{ $fullName }}
      sectionName: dns-udp
    {{- else }}
    {{- toYaml .Values.udpRoute.parentRefs | nindent 4 }}
    {{- end }}
  rules:
    - backendRefs:
        - name: {{ $fullName }}
          port: {{ .Values.service.dnsPort }}
{{- end }}
