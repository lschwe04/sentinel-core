# 🛡️ SentinelCore Hub

SentinelCore Hub is the central, multi-tenant management and control plane designed for IT service providers and managed service providers (MSPs). It aggregates telemetry, security hardening compliance, and system metrics securely via mTLS and WireGuard.

## 🚀 Key Features

* **Multi-Tenancy (B2B White-Label):** Manage multiple end-customers cleanly isolated within a single hub instance.
* **Zero-Trust Communication:** Strict mTLS (TLS 1.3) enforcement and token-based agent enrollment.
* **Compliance & Hardening:** Continuous tracking of CIS benchmarks and security logs.
* **Lightweight & Fast:** Built with Go, PostgreSQL (`pgxpool`), HTMX, and Tailwind CSS.

## 📦 Quick Start (Docker)

1. Clone the repository:
   ```bash
   git clone [https://github.com/your-username/sentinel-core.git](https://github.com/your-username/sentinel-core.git)
   cd sentinel-core

   Run via Docker Compose:
   docker-compose up -d

🔐 Security Architecture
All agent-to-hub communications require mutual TLS (mTLS). Database access is pooled securely using pgxpool with strict tenant scoping.

📄 License
Proprietary / Open Core - See LICENSE file for details.
