# SentinelCore Hub 🛡️

SentinelCore Hub ist die zentrale Management- und Steuerungseinheit für verteilte Enterprise-Infrastrukturen. Das System kombiniert modernste Cloud-Native-Technologien mit kompromisslosen Zero-Trust-Sicherheitsstandards.

## 🚀 Kernfunktionen

* **CIS Hardening Management:** Überwachung und automatisierte Durchsetzung von Compliance-Richtlinien (CIS Level 1 & Level 2)[cite: 11].
* **Live-Telemetrie:** Echtzeit-Auswertung von Systemmetriken (CPU, RAM, Disk) angebundener Nodes via `gopsutil`[cite: 11].
* **Backup-Überwachung:** Zentrales Monitoring von Restic-Snapshots und S3 Object-Lock-Status[cite: 11].
* **Security Audit Logs:** Echtzeit-Analyse von Sicherheitsereignissen aus Quellen wie Falco und Auditd[cite: 11].
* **Hybrides Server Provisioning:** Automatisierte Ausrollung über Terraform (Cloud-Provider wie Hetzner) oder direkt via Ansible (On-Premises)[cite: 11].
* **Reaktives UI:** Schlankes Frontend gesteuert über HTMX und Tailwind CSS ohne schweren JavaScript-Framework-Overhead[cite: 11].

---

## 🔒 Security & Architektur

* **Zero-Trust mTLS:** Kommunikation zwischen Hub und Agenten erzwingt standardmäßig mTLS (TLS 1.3) mit strikter Zertifikatsvalidierung[cite: 11].
* **Netzwerk-Isolation:** Anbindung erfolgt ausschließlich über dedizierte WireGuard-VPN-Tunnel[cite: 11].
* **Moderne Go-Architektur:** Implementiert in Go 1.22+ unter Nutzung des nativen `http.ServeMux` für maximale Performance und minimale Angriffsflächen[cite: 11].

---

## 🛠️ Technologie-Stack

* **Backend:** Go, `pgxpool` (PostgreSQL)[cite: 11]
* **Frontend:** HTMX, Tailwind CSS[cite: 11]
* **Infrastruktur & DevOps:** Docker (Distroless Images), Terraform, GitHub Actions CI/CD[cite: 11]

---

## 📦 Schnellstart (Docker Compose)

1. Repository klonen:
   ```bash
   git clone [https://github.com/lschwe04/sentinel-core.git](https://github.com/lschwe04/sentinel-core.git)
   cd sentinel-core
