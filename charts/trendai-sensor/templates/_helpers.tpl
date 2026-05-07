{{/*
Chart name, possibly truncated to 63 chars (the K8s label limit).
*/}}
{{- define "trendai-sensor.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name. Uses fullnameOverride if set, otherwise
Release.Name + chart name (collapsed if they match).
*/}}
{{- define "trendai-sensor.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "trendai-sensor.namespace" -}}
{{- default .Release.Namespace .Values.namespace.name -}}
{{- end -}}

{{- define "trendai-sensor.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "trendai-sensor.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "trendai-sensor.selectorLabels" -}}
app.kubernetes.io/name: {{ include "trendai-sensor.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app: {{ include "trendai-sensor.name" . }}
{{- end -}}

{{- define "trendai-sensor.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
