{{- $fullName := include "dhcpr.fullname" . -}}
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ $fullName }}
  labels:
    {{- include "dhcpr.labels" . | nindent 4 }}
