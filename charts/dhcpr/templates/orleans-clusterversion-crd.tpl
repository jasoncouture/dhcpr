# Orleans.Clustering.Kubernetes CRDs — install once per cluster (chart-managed).
# Upstream: https://github.com/OrleansContrib/Orleans.Clustering.Kubernetes
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: clusterversions.orleans.dot.net
  labels:
    {{- include "dhcpr.labels" . | nindent 4 }}
spec:
  group: orleans.dot.net
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            clusterId:
              type: string
            clusterVersion:
              type: integer
  scope: Namespaced
  names:
    plural: clusterversions
    singular: clusterversion
    kind: OrleansClusterVersion
    shortNames:
      - ocv
      - oc
