# SentinelCore Management Hub

SentinelCore zentralisiert Agenten-Enrollment, Telemetrie, CIS-Hardening und Audit-Events fuer Systemhaeuser. Die Beta verwendet TLS 1.3, mTLS auf dem privaten Listener, kurzlebige Ed25519-JWTs, Redis-Rate-Limiting und PostgreSQL-RLS.

## Beta-Start mit Docker Compose

1. Voraussetzungen installieren: Docker Compose, PostgreSQL, Redis und OpenSSL.
2. Zertifikate und Schluessel erzeugen oder aus Vault beziehen. Der Hub benoetigt `CA_CERT_PEM`, `CA_KEY_PEM`, ein Serverzertifikat unter `certs/server.crt`/`certs/server.key`, sowie `JWT_PRIVATE_KEY_PEM`, `JWT_PUBLIC_KEY_PEM`, `JWT_KEY_ID` und `JWT_REVOCATION_VERSION`.
3. `DATABASE_URL`, `REDIS_URL` und ein mindestens 32 Zeichen langes `JWT_SECRET` als Secrets setzen. `ALLOW_EPHEMERAL_CERTS=false` und `ALLOW_EPHEMERAL_JWT_KEYS=false` verwenden.
4. Stack starten:

   ```powershell
   docker compose -f docker-compose.yml up --build -d
   ```

5. Den privaten Healthcheck ueber den mTLS-Listener pruefen:

   ```powershell
   curl.exe --cacert ca.crt --cert operator.crt --key operator.key https://localhost:9443/healthz
   ```

## Beta-Start mit Helm

Setze die Pflichtwerte in einer nicht versionierten `beta-values.yaml`: `database.url`, `redis.url`, `secrets.jwtSecret`, `secrets.enterpriseAuthToken`, `secrets.caCertPEM`, `secrets.caKeyPEM`, `secrets.jwtPrivateKeyPEM`, `secrets.jwtPublicKeyPEM` und `secrets.jwtKeyID`.

```powershell
helm upgrade --install sentinel-core deployments/helm/sentinel-core `
  --namespace sentinel-core --create-namespace `
  --values beta-values.yaml
```

Der Chart aktiviert Non-Root, `RuntimeDefault`, ein read-only Root-Filesystem und Readiness/Liveness auf dem privaten Listener. Der Load Balancer muss fuer Port 9443 TCP-Passthrough oder TLS-Re-Encryption mit Client-Zertifikatsweitergabe verwenden.

## Agent-Zertifikate und Rollout

Der Agent erzeugt den privaten Schluessel lokal und sendet nur einen signierten CSR an `POST /enroll`. Der Enrollment-Token ist einmalig und tenantgebunden. Die Antwort enthaelt Shared Secret, Client-Zertifikat und CA-Zertifikat; private Schluessel werden niemals vom Hub erzeugt oder uebertragen.

1. Pro Tenant einen kurzlebigen Enrollment-Token erzeugen.
2. Agent mit Hub-URL, Token und lokalem CSR ausrollen.
3. Client-Zertifikat und CA installieren und danach den privaten Listener verwenden.
4. Mit Heartbeat, Telemetrie und Command-Ack in Staging testen; erst dann den Rollout staffeln.

Vor Produktion: RLS-Cross-Tenant-Tests, Redis-Failover, Zertifikatsrotation, Backup/Restore und `go test ./...` ausfuehren. Fuer `go test -race` ist eine Go-Toolchain mit aktiviertem CGO und C-Compiler erforderlich.
