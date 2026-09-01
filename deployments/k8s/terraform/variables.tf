variable "node_name" {
  type        = string
  description = "Eindeutiger Name des Zielservers"
}

variable "environment" {
  type        = string
  default     = "production"
  description = "Umgebung (staging, production)"
}

variable "server_type" {
  type        = string
  default     = "cx22"
  description = "Instanz-Größe beim Cloud-Provider"
}
