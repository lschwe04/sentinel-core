{{- if .Values.serviceMonitor.enabled }}
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: {{ include "sentinel-core.fullname" . }}
spec:
  selector:
    matchLabels:
      app: {{ include "sentinel-core.fullname" . }}
  endpoints:
    - port: private
      path: /metrics
      scheme: https
{{- end }}