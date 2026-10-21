{{- define "nanobot-k8s.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "nanobot-k8s.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "nanobot-k8s.labels" -}}
app.kubernetes.io/name: {{ include "nanobot-k8s.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "nanobot-k8s.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nanobot-k8s.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "nanobot-k8s.secretName" -}}
{{- default (printf "%s-credentials" (include "nanobot-k8s.fullname" .)) .Values.credentials.existingSecret -}}
{{- end -}}
