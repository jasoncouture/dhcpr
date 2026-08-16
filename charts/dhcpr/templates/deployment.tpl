apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "dhcpr.fullname" . }}
  labels:
    {{- include "dhcpr.labels" . | nindent 4 }}
    orleans/serviceId: dhcpr
    orleans/clusterId: dhcpr
  {{- with (include "dhcpr.annotations" .) }}
  annotations:
    {{- . | nindent 4 }}
  {{- end }}
spec:
  replicas: {{ .Values.replicaCount }}
  {{- with .Values.strategy }}
  strategy:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  selector:
    matchLabels:
      {{- include "dhcpr.labels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "dhcpr.labels" . | nindent 8 }}
        orleans/serviceId: dhcpr
        orleans/clusterId: dhcpr
      {{- with (include "dhcpr.annotations" .) }}
      annotations:
        {{- . | nindent 8 }}
      {{- end }}
    spec:
      serviceAccountName: {{ include "dhcpr.fullname" . }}
      containers:
        - name: dhcpr
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          ports:
            - name: http
              containerPort: 8080
              protocol: TCP
            - name: dns-udp
              containerPort: 53
              protocol: UDP
            - name: dns-tcp
              containerPort: 53
              protocol: TCP
            - name: orleans-silo
              containerPort: 11111
              protocol: TCP
            - name: orleans-gw
              containerPort: 30000
              protocol: TCP
          env:
            - name: POD_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
            - name: POD_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
            - name: POD_IP
              valueFrom:
                fieldRef:
                  fieldPath: status.podIP
            - name: ORLEANS_SERVICE_ID
              valueFrom:
                fieldRef:
                  fieldPath: metadata.labels['orleans/serviceId']
            - name: ORLEANS_CLUSTER_ID
              valueFrom:
                fieldRef:
                  fieldPath: metadata.labels['orleans/clusterId']
            {{- with .Values.env }}
            {{- toYaml . | nindent 12 }}
            {{- end }}
          {{- with .Values.envFrom }}
          envFrom:
            {{- toYaml . | nindent 12 }}
          {{- end }}
          volumeMounts:
            - name: data
              mountPath: /data
          livenessProbe:
            {{- toYaml .Values.livenessProbe | nindent 12 }}
          readinessProbe:
            {{- toYaml .Values.readinessProbe | nindent 12 }}
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: {{ include "dhcpr.fullname" . }}-data
