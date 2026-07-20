apiVersion: v1
kind: Service
metadata:
  name: {{ include "dhcpr.fullname" . }}
  labels:
    {{- include "dhcpr.labels" . | nindent 4 }}
spec:
  type: {{ .Values.service.type }}
  selector:
    {{- include "dhcpr.labels" . | nindent 4 }}
  ports:
    - name: http
      port: {{ .Values.service.httpPort }}
      targetPort: http
      protocol: TCP
    - name: dns-udp
      port: {{ .Values.service.dnsPort }}
      targetPort: dns-udp
      protocol: UDP
    - name: dns-tcp
      port: {{ .Values.service.dnsPort }}
      targetPort: dns-tcp
      protocol: TCP
