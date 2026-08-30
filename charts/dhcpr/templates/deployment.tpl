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
            {{- if .Values.secureDns.enabled }}
            - name: https
              containerPort: {{ .Values.secureDns.dohPort | default 443 }}
              protocol: TCP
            - name: dns-tls
              containerPort: {{ .Values.secureDns.dotPort }}
              protocol: TCP
            {{- end }}
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
            {{- if .Values.secureDns.enabled }}
            {{- if and (not .Values.secureDns.existingSecret) (not .Values.secureDns.certManager.enabled) }}
            {{- fail "secureDns.enabled requires existingSecret or certManager.enabled" }}
            {{- end }}
            {{- if or (not .Values.secureDns.certManager.dnsNames) (not (index .Values.secureDns.certManager.dnsNames 0)) }}
            {{- fail "secureDns.certManager.dnsNames is required when secureDns is enabled" }}
            {{- end }}
            - name: DOTNET_URLS
              value: "http://+:8080;https://+:{{ .Values.secureDns.dohPort | default 443 }}"
            - name: TLS__Enabled
              value: "true"
            - name: TLS__Listeners__0
              value: "0.0.0.0:{{ .Values.secureDns.dotPort }}"
            - name: TLS__Listeners__1
              value: "[::]:{{ .Values.secureDns.dotPort }}"
            - name: TLS__CertificatePath
              value: /tls/tls.crt
            - name: TLS__PrivateKeyPath
              value: /tls/tls.key
            - name: TLS__HttpsPort
              value: "{{ .Values.secureDns.dohPort | default 443 }}"
            {{- $dnsName := index .Values.secureDns.certManager.dnsNames 0 }}
            - name: DNS__DesignatedResolvers__0__Target
              value: {{ $dnsName | quote }}
            - name: DNS__DesignatedResolvers__0__Priority
              value: "1"
            - name: DNS__DesignatedResolvers__0__Alpn__0
              value: "dot"
            - name: DNS__DesignatedResolvers__0__Port
              value: "{{ .Values.secureDns.dotPort }}"
            - name: DNS__DesignatedResolvers__1__Target
              value: {{ $dnsName | quote }}
            - name: DNS__DesignatedResolvers__1__Priority
              value: "2"
            - name: DNS__DesignatedResolvers__1__Alpn__0
              value: "h2"
            - name: DNS__DesignatedResolvers__1__Port
              value: "{{ .Values.secureDns.dohPort | default 443 }}"
            - name: DNS__DesignatedResolvers__1__DohPath
              value: "/dns-query{?dns}"
            {{- end }}
          {{- with .Values.envFrom }}
          envFrom:
            {{- toYaml . | nindent 12 }}
          {{- end }}
          volumeMounts:
            - name: data
              mountPath: /data
            {{- if .Values.secureDns.enabled }}
            - name: tls
              mountPath: /tls
              readOnly: true
            {{- end }}
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
        {{- if .Values.secureDns.enabled }}
        - name: tls
          secret:
            secretName: {{ include "dhcpr.secureDnsSecretName" . }}
        {{- end }}
