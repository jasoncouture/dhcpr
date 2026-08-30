{{- define "dhcpr.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default "dhcpr" .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "dhcpr.labels" -}}
app.kubernetes.io/name: dhcpr
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "dhcpr.annotations" -}}
{{- with .Values.annotations }}
{{- toYaml . }}
{{- end }}
{{- end }}

{{- define "dhcpr.secureDnsSecretName" -}}
{{- if .Values.secureDns.existingSecret }}
{{- .Values.secureDns.existingSecret }}
{{- else }}
{{- .Values.secureDns.certManager.secretName | default (printf "%s-secure-dns-tls" (include "dhcpr.fullname" .)) }}
{{- end }}
{{- end }}
