{{- $fullName := include "dhcpr.fullname" . -}}
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ $fullName }}
  labels:
    {{- include "dhcpr.labels" . | nindent 4 }}
---
# Orleans.Hosting.Kubernetes probes pods for membership cleanup.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ $fullName }}-orleans
  labels:
    {{- include "dhcpr.labels" . | nindent 4 }}
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "watch", "list", "delete", "patch"]
  # Orleans.Clustering.Kubernetes may manage ClusterMember CRDs when installed.
  - apiGroups: ["orleans.dot.net"]
    resources: ["clusterversions", "silos"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ $fullName }}-orleans
  labels:
    {{- include "dhcpr.labels" . | nindent 4 }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ $fullName }}-orleans
subjects:
  - kind: ServiceAccount
    name: {{ $fullName }}
    namespace: {{ .Release.Namespace }}
