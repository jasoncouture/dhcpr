{{- if and .Values.httpRoute.enabled .Values.httpRoute.sticky.enabled }}
{{- $fullName := include "dhcpr.fullname" . -}}
{{- $cookieName := default $fullName .Values.httpRoute.sticky.cookie.name -}}
apiVersion: traefik.io/v1alpha1
kind: TraefikService
metadata:
  name: {{ printf "%s-sticky" $fullName }}
  labels:
    {{- include "dhcpr.labels" . | nindent 4 }}
spec:
  weighted:
    services:
      - name: {{ $fullName }}
        port: {{ .Values.service.httpPort }}
        sticky:
          cookie:
            name: {{ $cookieName | quote }}
            httpOnly: {{ .Values.httpRoute.sticky.cookie.httpOnly }}
            secure: {{ .Values.httpRoute.sticky.cookie.secure }}
{{- end }}
