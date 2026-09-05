# SentinelCore Management Hub 🛡️

SentinelCore ist eine Enterprise-Plattform für zentrales Sicherheits-, Compliance- und Infrastruktur-Management (CIS-Hardening, mTLS, FIM und Audit-Logging) für Systemhäuser und IT-Dienstleister.

## 🚀 Key Features
- **Zero-Trust Agenten-Enrollment:** Automatische Registrierung über kryptografische Hardware-Fingerprints & Einmal-Tokens.
- **CIS Hardening & Remediation:** Automatisierte Durchsetzung von CIS-Level-1/2-Profilen via Ansible & Terraform.
- **Manipulationssichere Audit-Logs:** Kryptografisch verkettete SHA-256 Logs für DSGVO- und Compliance-Nachweise.
- **Enterprise Security:** Erzwingung von mTLS (TLS 1.3), JWT-Authentifizierung & Microsoft Entra ID SSO.

---

## ⚡ Quick Start (Lokal via Docker Compose)

1. **Repository klonen & Umgebung konfigurieren:**
   ```bash
   git clone [https://github.com/lschwe04/sentinel-core.git](https://github.com/lschwe04/sentinel-core.git)
   cd sentinel-core
   cp configs/config.yaml.example configs/config.yaml # Ggf. anpassen

Stack starten (Hub + PostgreSQL + Prometheus):

docker-compose up --build -d

Gesundheitsstatus prüfen:

curl -k https://localhost:8443/health
