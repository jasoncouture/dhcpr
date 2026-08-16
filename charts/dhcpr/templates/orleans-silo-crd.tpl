# Orleans.Clustering.Kubernetes CRDs — install once per cluster (chart-managed).
# Upstream: https://github.com/OrleansContrib/Orleans.Clustering.Kubernetes
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: silos.orleans.dot.net
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
          required:
            - address
            - port
            - generation
            - hostname
            - status
            - siloName
          type: object
          properties:
            clusterId:
              type: string
            address:
              type: string
            port:
              type: integer
            generation:
              type: integer
            hostname:
              type: string
            status:
              type: string
            proxyPort:
              type: integer
            siloName:
              type: string
            suspectingSilos:
              type: array
              items:
                type: string
            suspectingTimes:
              type: array
              items:
                type: string
            startTime:
              type: string
            iAmAliveTime:
              type: string
  scope: Namespaced
  names:
    plural: silos
    singular: silo
    kind: OrleansSilo
    shortNames:
      - oso
      - os
