output "node_ip" {
  value       = hcloud_server.node.ipv4_address
  description = "Die öffentliche IPv4-Adresse der neuen Cloud-Instanz für das Ansible-Bootstrapping"
}

output "node_id" {
  value       = hcloud_server.node.id
  description = "Interne ID der Instanz"
}
