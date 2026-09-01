terraform {
  required_version = ">= 1.6.0"
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.45.0"
    }
  }
}

provider "hcloud" {
  // Token wird über die Umgebungsvariable HCLOUD_TOKEN injiziert
}

resource "hcloud_server" "node" {
  name        = var.node_name
  image       = "rocky-9"
  server_type = var.server_type
  location    = "fsn1"
  labels = {
    managed_by    = "sentinel-core"
    environment   = var.environment
    hardening_lvl = var.hardening_level
  }

  user_data = <<-EOF
              #cloud-config
              package_update: true
              packages:
                - wireguard
                - curl
                - git
                - ansible
                - lynis
                - prometheus-node-exporter
              runcmd:
                - systemctl enable --now prometheus-node-exporter
                - echo "Node bootstrapped with SentinelCore. Hardening level: ${var.hardening_level}" > /etc/sentinel_bootstrap.log
              EOF
}
