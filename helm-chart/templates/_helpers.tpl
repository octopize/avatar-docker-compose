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
{{- if .Values.serviceAccount.create }}
{{- default (include "avatar.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
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
            - name: CELERY_BROKER_URL
              valueFrom:
                configMapKeyRef:
                  name: avatar-config
                  key: CELERY_BROKER_URL
            - name: CELERY_RESULT_BACKEND
              valueFrom:
                configMapKeyRef:
                  name: avatar-config
                  key: CELERY_RESULT_BACKEND
            - name: BASE_API_URL
              valueFrom:
                configMapKeyRef:
                  name: avatar-config
                  key: BASE_API_URL
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
            - name: PDFGENERATOR_URL
              valueFrom:
                configMapKeyRef:
                  name: avatar-config
                  key: PDFGENERATOR_URL
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
            - name: CLEVERCLOUD_SSO_SALT
              valueFrom:
                configMapKeyRef:
                  name: avatar-config
                  key: CLEVERCLOUD_SSO_SALT
            - name: DELETE_FILES_USING_CRONJOB
              value: "false"
{{- end }}

{{/*
Define the Google Cloud SQL proxy if necessary
Documentation: https://cloud.google.com/sql/docs/mysql/connect-kubernetes-engine
*/}}
{{- define "avatar.db_proxy_container" }}
{{- if $.Values.gcp.dbInstanceConnectionName }}
        - name: cloud-sql-proxy
          image: gcr.io/cloud-sql-connectors/cloud-sql-proxy:2.5.0 # make sure the use the latest version
          command:
            - "/cloud-sql-proxy"
            - "--auto-ip"
            - "--quitquitquit"
            # Unused for now
            # - "-enable_iam_login"
            - "{{ $.Values.gcp.dbInstanceConnectionName }}"
          securityContext:
            runAsNonRoot: true
          resources:
            requests:
              memory: "1Gi"
              cpu:    "1"

{{- end }}
{{- end }}
