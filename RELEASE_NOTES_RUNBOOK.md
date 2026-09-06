# SentinelCore Hub
## Release Notes & Deployment Runbook

**Release:** Phase 2 Enterprise Readiness
**Zielgruppe:** DevOps, SRE, Security Operations
**Geltungsbereich:** DACH-Staging und Produktion

## 1. Change Summary

### Netzwerk und mTLS

- Der Hub startet zwei HTTPS-Listener:
  - `PUBLIC_PORT` (Default `8443`): ausschließlich `POST /enroll`, ohne Client-Zertifikat.
  - `PRIVATE_PORT` (Default `9443`): Management-, Agent- und JWKS-Endpunkte mit TLS 1.3 und `RequireAndVerifyClientCert`.
- Agentenzertifikate werden zusätzlich zu CA-Validierung und Fingerprint gegen `node_id` und den Tenant-Subject geprüft.
- Ephemere Serverzertifikate sind nur mit `ALLOW_EPHEMERAL_CERTS=true` möglich und für Produktion verboten.

### Kryptografie und Identität

- Enrollment akzeptiert einen signierten CSR und erzeugt keinen privaten Agentenschlüssel mehr.
- Agentenzertifikate enthalten Node-ID und Tenant-Organisation.
- JWTs werden mit Ed25519, `kid`, kurzer TTL, `jti` und Revocation-Version ausgestellt.
- JWKS ist unter `/.well-known/jwks.json` verfügbar.
- Für ältere lokale/Kompatibilitätsfälle existiert weiterhin ein HS256-Fallback. Dieser darf in Produktion nicht als alleiniger Verifikationspfad eingesetzt werden.

### Mandantentrennung

- `migrations/06_enterprise_security.sql` ergänzt `tenant_id`, Foreign Keys, Indizes und RLS-Policies für Telemetrie-, Security- und Hardening-Daten.
- `db.WithTenantTx` setzt `app.tenant_id` lokal innerhalb einer kurzlebigen PostgreSQL-Transaktion.
- Agenten-Telemetrie und Hardening-Writes verwenden diesen Tenant-Kontext.

### Rate-Limiting und Events

- Agentenrequests werden nach erfolgreicher Agent-Authentifizierung über Redis limitiert.
- Redis-Ausfall ist fail-closed und liefert `503`.
- Alert- und Audit-Events werden in `event_outbox` persistiert.
- Der Worker verwendet `FOR UPDATE SKIP LOCKED`, Retry-Backoff, Deduplication und Dead-Letter-Queue.
- Webhook-Ziele werden auf erlaubte HTTP(S)-Ziele sowie private und Loopback-Adressen geprüft.

### Reports und Abhängigkeiten

- Compliance- und AVV-Reports können serverseitig als PDF erstellt werden.
- Neue Runtime-Abhängigkeiten: Redis-Client und PDF-Renderer.

## 2. Harte Operating Conditions

### PostgreSQL und RLS

1. Die Anwendung muss mit einem dedizierten DB-User laufen, der **nicht** Tabellenbesitzer ist und weder `BYPASSRLS` noch Superuser-Rechte besitzt.
2. `app.tenant_id` darf nur innerhalb einer Transaktion gesetzt werden:

   ```sql
   SELECT set_config('app.tenant_id', '<numeric-tenant-id>', true);
   ```

3. Alle RLS-geschützten Statements müssen dieselbe Transaktion wie `set_config` verwenden. Keine RLS-Lese-/Schreiboperation mit `db.Pool.Query` außerhalb eines Tenant-Kontexts.
4. Bei PgBouncer ist `pool_mode=transaction` zulässig, weil der Code den GUC mit `is_local=true` transaktionslokal setzt. `pool_mode=session` erfordert zusätzlich eine strikte Reset-Policy und darf keine Tenant-GUCs zwischen Requests wiederverwenden.
5. PgBouncer darf keine Statements aus einer Tenant-Transaktion auf eine andere Backend-Connection verschieben. Prepared-Statement-Konfiguration und Pooler-Modus müssen in Staging mit Cross-Tenant-Tests geprüft werden.
6. Der DB-User darf die RLS-Policies nicht umgehen. Das muss mit `SELECT rolbypassrls, rolsuper FROM pg_roles` verifiziert werden.
7. Vor Aktivierung der Policies müssen alle bestehenden Datensätze einem Tenant zugeordnet sein. Nicht zuordenbare Datensätze werden nicht automatisch sicher sichtbar und müssen vor dem Cutover bereinigt werden.

### Redis

- `REDIS_URL` ist zwingend erforderlich.
- Für Produktion Redis Sentinel oder Redis Cluster mit:
  - TLS und ACL-User,
  - mindestens drei Failure Domains,
  - persistenter Monitoring-/Alerting-Anbindung,
  - getesteter Failover-Zeit unter dem API-SLO.
- Der Rate-Limiter läuft fail-closed. Bei Redis-Ausfall werden Agentenrequests mit `503` abgewiesen.
- Der Redis-Key darf ausschließlich aus dem authentifizierten Context stammen. `X-Tenant-ID` ist kein zulässiger Rate-Limit-Schlüssel.
- Die aktuelle Konfiguration verwendet ein Tenant-Fenster von 300 Requests pro Minute. Änderungen müssen Lasttests und Kapazitätsplanung durchlaufen.

### Load Balancer und Netzwerk

- Der Public-Listener darf regulär am Load Balancer terminiert werden. Er darf ausschließlich `/enroll` an den Hub weiterleiten.
- Für den Private-Listener ist TCP-Passthrough erforderlich, damit der Hub das Client-Zertifikat selbst sieht und `RequireAndVerifyClientCert` durchsetzt.
- Alternativ ist TLS-Re-Encryption mit vollständiger Client-Zertifikatsweitergabe zulässig, sofern der Hub weiterhin die echte Peer-Zertifikatskette erhält. Reines TLS-Terminieren am LB ohne mTLS-Re-Encryption ist nicht zulässig.
- Private Listener, Redis, PostgreSQL und Vault gehören in ein internes Netzwerksegment. Der Public Listener darf keinen Zugriff auf Management-, Agent-, Download- oder JWKS-Pfade erlauben.
- Healthchecks dürfen nicht auf `/enroll` als erfolgreiche Anwendungserreichbarkeit umgedeutet werden. Ein dedizierter interner Healthcheck muss über die private Route bereitgestellt werden.

### Secrets und Key Management

Unterstützte Konfigurationsvariablen:

```text
DATABASE_URL
REDIS_URL
CA_CERT_PEM
CA_KEY_PEM
JWT_SECRET
JWT_PRIVATE_KEY_PEM
JWT_PUBLIC_KEY_PEM
JWT_KEY_ID
JWT_REVOCATION_VERSION
JWT_ISSUER
JWT_AUDIENCE
VAULT_ADDR
VAULT_TOKEN
VAULT_SECRET_PATH
PUBLIC_PORT=8443
PRIVATE_PORT=9443
ALLOW_EPHEMERAL_CERTS=false
ALLOW_EPHEMERAL_JWT_KEYS=false
```

- Produktionsschlüssel müssen aus Vault/KMS oder einem Vault-Agent mit kurzlebiger Zugriffserlaubnis bezogen werden.
- `CA_KEY_PEM` und `JWT_PRIVATE_KEY_PEM` dürfen nicht in Git, Container-Images, Helm Values oder CI-Logs erscheinen.
- Die vorhandene Secret-Provider-Schicht liest `JWT_SECRET` und CA-Werte aus Vault oder Environment. Der aktuelle `SecurityManager` liest `JWT_PRIVATE_KEY_PEM` und `JWT_PUBLIC_KEY_PEM` direkt aus der Umgebung; bis zur Erweiterung des Providers müssen diese beiden Werte durch Vault-Agent-Injektion bereitgestellt werden.
- `JWT_SECRET` bleibt aktuell als Startvoraussetzung mit mindestens 32 Zeichen erforderlich, auch wenn der produktive Signaturpfad Ed25519 verwendet. Es muss daher als verschlüsseltes Kompatibilitätssecret vorhanden sein.
- Key Rotation erfolgt über neuen `kid`, parallele JWKS-Veröffentlichung, Token-TTL-Abwarten und anschließendes Entfernen des alten Public Keys. Eine Änderung von `JWT_REVOCATION_VERSION` invalidiert alle Tokens dieser Version.

## 3. Migrations- und Deployment-Pfad

### 3.1 Vorprüfung in Staging

1. Release-Artefakt, Go-Modul-Checksums und alle neuen Dateien in den Release-Commit aufnehmen. Besonders prüfen:
   - `migrations/06_enterprise_security.sql`
   - `internal/auth/jwks.go`
   - `internal/auth/jwt_verify.go`
   - `internal/auth/redis_ratelimit.go`
   - `internal/config/`
   - `internal/db/tenant.go`
   - `internal/services/outbox.go`
2. `go test ./...` ausführen.
3. TLS-Serverzertifikat, CA-Zertifikat und Ed25519-JWT-Schlüsselpaar erzeugen bzw. aus Vault beziehen.
4. Prüfen, dass `JWT_PUBLIC_KEY_PEM` exakt zum privaten Schlüssel gehört und `JWT_KEY_ID` gesetzt ist.
5. Redis-Failover testen: während laufender Agentenrequests einen Sentinel-/Cluster-Failover auslösen. Erwartung: kontrollierte `503`-Antworten, keine unlimitierten Requests.
6. Mit zwei Test-Tenants Cross-Tenant-Reads und Writes ausführen. Jeder Zugriff ohne korrekt gesetztes `app.tenant_id` muss leer oder abgewiesen werden.

### 3.2 Datenbankmigration

Die Datei `migrations/06_enterprise_security.sql` ist im aktuellen Codebestand eine separate SQL-Migration und wird nicht automatisch durch den bestehenden inline definierten `RunMigrations`-Block ausgeführt.

1. Backup und Restore-Test der Produktionsdatenbank durchführen.
2. Migration mit einem dedizierten Schema-Migrationsuser ausführen:

   ```powershell
   psql "$env:DATABASE_URL" --set ON_ERROR_STOP=1 --file migrations/06_enterprise_security.sql
   ```

3. Vor Freigabe der RLS-Policies prüfen, ob verwaiste Datensätze verbleiben:

   ```sql
   SELECT COUNT(*) FROM node_metrics WHERE tenant_id IS NULL;
   SELECT COUNT(*) FROM security_logs WHERE tenant_id IS NULL;
   SELECT COUNT(*) FROM hardening_status WHERE tenant_id IS NULL;
   ```

   Alle Ergebnisse müssen `0` sein oder über einen freigegebenen Datenbereinigungsplan behandelt werden.
4. Rollenrechte prüfen:

   ```sql
   SELECT rolname, rolsuper, rolbypassrls
   FROM pg_roles
   WHERE rolname = current_user;
   ```

5. Outbox- und Dead-Letter-Indizes sowie Tabellenwachstum in Monitoring aufnehmen.

### 3.3 Secrets und Infrastruktur aktivieren

1. Vault/KMS-Secrets bereitstellen und Zugriff vom Hub-Service testen.
2. `CA_CERT_PEM`, `CA_KEY_PEM`, `JWT_PRIVATE_KEY_PEM`, `JWT_PUBLIC_KEY_PEM`, `JWT_KEY_ID`, `JWT_REVOCATION_VERSION`, `JWT_ISSUER` und `JWT_AUDIENCE` setzen.
3. `DATABASE_URL` auf den RLS-kompatiblen App-User umstellen.
4. `REDIS_URL` auf den TLS-geschützten Sentinel-/Cluster-Endpunkt setzen.
5. `PUBLIC_PORT` und `PRIVATE_PORT` festlegen und Firewall-/Security-Group-Regeln veröffentlichen.
6. `ALLOW_EPHEMERAL_CERTS=false` und `ALLOW_EPHEMERAL_JWT_KEYS=false` explizit setzen.

### 3.4 Staged Cutover

1. Neue Hub-Version zunächst mit altem Agentenbestand in Staging starten.
2. Bestehende Agenten mit bereits gespeicherten Zertifikats-Fingerprints testen. Sie bleiben kompatibel, sofern ihr Zertifikat von der konfigurierten Client-CA stammt und `CommonName` sowie Tenant-Organisation den gespeicherten Identitäten entsprechen.
3. Einen neuen Agenten mit CSR enrollen und den vollständigen Ablauf prüfen:
   - Public `/enroll` erreichbar,
   - privater Schlüssel bleibt auf dem Agenten,
   - Zertifikat wird auf Private Listener akzeptiert,
   - falscher Fingerprint, Node oder Tenant wird abgewiesen.
4. Management-Login mit Ed25519-JWT und JWKS-Verifikation testen.
5. Outbox-Event erzeugen und Zustellung, Retry, Recovery und Dead-Letter-Verhalten prüfen.
6. Erst danach Produktion auf den neuen Private Listener und die neuen LB-Regeln umschalten.

### 3.5 Abwärtskompatibilität

- **Alte Agentenzertifikate:** Es gibt keinen pauschalen Zertifikats-Grace-Period-Schalter. Bestehende Zertifikate funktionieren weiter, wenn CA, Fingerprint, Node-ID und Tenant-Subject die neuen Prüfungen erfüllen. Zertifikate außerhalb dieser Bedingungen müssen neu ausgerollt werden.
- **Alte, hubgenerierte private Schlüssel:** Der Hub erzeugt und liefert ab diesem Release keine privaten Schlüssel mehr. Bereits ausgerollte Schlüssel werden nicht erneut exponiert und können bis zum Zertifikatsablauf verwendet werden.
- **CSR-Enrollment:** Für neue Agenten ist CSR verpflichtend. Für den Rollout sollte eine 30-tägige operative Übergangsfrist für die Agentenverteilung geplant werden; sie ist jedoch kein automatisch implementierter Server-Grace-Period-Mechanismus.
- **HS256-JWTs:** Mit gesetztem `JWT_PUBLIC_KEY_PEM` wird Ed25519 verifiziert. Eine produktionsfähige duale HS256/Ed25519-Grace-Period ist im aktuellen Code nicht implementiert. Alte HS256-Sessiontokens müssen vor Cutover auslaufen oder durch einen kontrollierten Legacy-Verifier in einer separaten Übergangsversion akzeptiert werden. Für den sicheren Rollout: TTL der alten Sessions abwarten, Cookies invalidieren und neue Sessions ausstellen.

## 4. Outbox-Worker und Skalierung

Der aktuelle Code startet den Worker in `services.StartAlertEngine()` direkt beim Hub-Start. Der Worker läuft als Goroutine im selben Prozess und pollt alle zwei Sekunden `event_outbox`:

```go
services.StartAlertEngine()
```

`FOR UPDATE SKIP LOCKED` erlaubt mehrere Hub-Instanzen, aber jede Instanz startet auch einen Worker. Für den aktuellen Release gilt daher:

- Worker-Last in die Hub-Kapazitätsplanung aufnehmen.
- Outbox-Lag, `processing`-Events, `dead`-Events und Zustellfehler überwachen.
- Bei horizontaler Skalierung sicherstellen, dass DB-Pool und Webhook-Limits nicht durch zu viele Worker überlastet werden.

Für den nächsten Hardening-Schritt sollte `processOutbox` in ein separates `cmd/outbox-worker`-Binary ausgelagert werden. Dieses wird unabhängig skaliert, erhält nur DB-/Webhook-/Vault-Rechte und läuft als eigenes Deployment mit HPA auf Outbox-Lag.

## 5. Release- und SRE-Checks

### Vor Go-Live

- [ ] `git status` enthält keine unbeabsichtigten Dateien; alle neuen Dateien sind versioniert.
- [ ] `go test ./...` grün.
- [ ] SQL-Migration erfolgreich und reversibles DB-Backup vorhanden.
- [ ] Keine `NULL`-Tenant-IDs in RLS-Tabellen.
- [ ] App-DB-User hat kein `BYPASSRLS`.
- [ ] Public LB leitet nur `/enroll` weiter.
- [ ] Private LB nutzt TCP-Passthrough oder mTLS-Re-Encryption.
- [ ] Redis TLS/Sentinel/Cluster-Failover getestet.
- [ ] JWKS, `kid`, Issuer, Audience und Revocation-Version geprüft.
- [ ] Vault/KMS-Zugriff und Rotation getestet.
- [ ] Outbox Retry und Dead-Letter-Alarm getestet.

### Laufzeitalarme

- Redis nicht erreichbar oder Rate-Limiter `503`.
- Outbox-Lag über SLO.
- `event_dead_letters` wächst.
- RLS-Fehler oder fehlender `app.tenant_id`-Kontext.
- Zertifikatsfehler am Private Listener.
- JWKS-Key- oder Revocation-Version-Mismatch.
- Webhook-SSRF-Ablehnungen und wiederholte Zustellfehler.

## 6. Validierungsstand

Zum Erstellungszeitpunkt dieses Dokuments war der Go-Testlauf erfolgreich:

```text
go test ./...
```

Der Git-Arbeitsbaum enthält die oben genannten Änderungen als nicht committete Änderungen. Vor einem Release muss daraus ein geprüfter Commit bzw. ein signiertes Release-Artefakt erstellt werden.
