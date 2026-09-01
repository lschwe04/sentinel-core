terraform {
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.45"
    }
  }
}

variable "node_name" {
  type        = string
  description = "Name des neuen Nodes, der vom Sentinel-Hub übergeben wird"
}

variable "provider" {
  type        = string
  description = "Infrastruktur-Provider (z.B. hetzner, aws)"
}

provider "hcloud" {
  # Token wird aus der Umgebungsvariable HCLOUD_TOKEN gelesen
}

resource "hcloud_server" "sentinel_node" {
  name        = var.node_name
  image       = "rocky-9" # Rocky Linux für CIS Compliance
  server_type = "cx21"
  location    = "fsn1"
  
  # Bootstrapping des WireGuard-Tunnels und des Agents
  user_data = <<-EOF
              #!/bin/bash
              dnf install -y wireguard-tools
              # Hier folgt der automatisierte WG-Key-Austausch und der Download des sentinel-agent.deb
              EOF
}

output "node_ip" {
  value = hcloud_server.sentinel_node.ipv4_address
}
