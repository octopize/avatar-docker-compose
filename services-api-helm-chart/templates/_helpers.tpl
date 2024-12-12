{{/*
Expand the name of the chart.
*/}}
{{- define "avatar.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "avatar.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "avatar.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "avatar.labels" -}}
helm.sh/chart: {{ include "avatar.chart" . }}
{{ include "avatar.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "avatar.selectorLabels" -}}
app.kubernetes.io/name: {{ include "avatar.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "avatar.serviceAccountName" -}}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}

{{/*
Define the default app env variables
*/}}
{{- define "avatar.app_env" }}
            - name: ENV_NAME
              valueFrom:
                configMapKeyRef:
                  name: avatar-config
                  key: ENV_NAME
            - name: AVATAR_API_URL
              valueFrom:
                configMapKeyRef:
                  name: avatar-config
                  key: AVATAR_API_URL
            - name: IS_SENTRY_ENABLED
              valueFrom:
                configMapKeyRef:
                  name: avatar-config
                  key: IS_SENTRY_ENABLED
            - name: IS_TELEMETRY_ENABLED
              valueFrom:
                configMapKeyRef:
                  name: avatar-config
                  key: IS_TELEMETRY_ENABLED
            - name: DB_HOST
              valueFrom:
                configMapKeyRef:
                  name: avatar-config
                  key: DB_HOST
            - name: DB_PORT
              valueFrom:
                configMapKeyRef:
                  name: avatar-config
                  key: DB_PORT
            - name: SHARED_STORAGE_PATH
              valueFrom:
                configMapKeyRef:
                  name: avatar-config
                  key: SHARED_STORAGE_PATH
            {{- if .Values.api.awsEndpointUrl }}
            - name: AWS_ENDPOINT_URL
              valueFrom:
                configMapKeyRef:
                  name: avatar-config
                  key: AWS_ENDPOINT_URL
            {{- end }}
            - name: AVATAR_PDFGENERATOR_URL
              valueFrom:
                configMapKeyRef:
                  name: avatar-config
                  key: AVATAR_PDFGENERATOR_URL
            - name: AWS_ACCESS_KEY_ID
              valueFrom:
                secretKeyRef:
                  name: api
                  key: aws_storage_account_access_key_id
            - name: AWS_SECRET_ACCESS_KEY
              valueFrom:
                secretKeyRef:
                  name: api
                  key: aws_storage_account_secret_access_key
            - name: MAX_ALLOWED_DIMENSIONS_PER_DATASET
              valueFrom:
                configMapKeyRef:
                  name: avatar-config
                  key: MAX_ALLOWED_DIMENSIONS_PER_DATASET
            - name: MAX_ALLOWED_LINES_PER_DATASET
              valueFrom:
                configMapKeyRef:
                  name: avatar-config
                  key: MAX_ALLOWED_LINES_PER_DATASET
            - name: LOG_LEVEL
              valueFrom:
                configMapKeyRef:
                  name: avatar-config
                  key: LOG_LEVEL
            - name: DELETE_FILES_USING_CRONJOB
              valueFrom:
                configMapKeyRef:
                  name: avatar-config
                  key: DELETE_FILES_USING_CRONJOB
{{- end }}

{{/*
Define the Google Cloud SQL proxy if necessary
Documentation: https://cloud.google.com/sql/docs/mysql/connect-kubernetes-engine
*/}}
{{- define "avatar.db_proxy_container" }}
{{- if $.Values.gcp.dbInstanceConnectionName }}
        - name: cloud-sql-proxy
          image: gcr.io/cloud-sql-connectors/cloud-sql-proxy:2.8.1-bullseye # make sure to use the latest version
          lifecycle:
            preStop:
              exec:
                command: ["/bin/sh", "-c", "sleep 3605"] # sleep for `terminationGracePeriodSeconds` + 5
          command:
            - "/cloud-sql-proxy"
            - "--auto-ip"
            - "--quitquitquit"
            - "{{ $.Values.gcp.dbInstanceConnectionName }}"
          securityContext:
            runAsNonRoot: true
          resources:
            requests:
              memory: "256Mi"
              cpu:    "100m"
{{- end }}
{{- end }}
