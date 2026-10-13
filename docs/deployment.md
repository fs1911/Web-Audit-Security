# Deployment

> **Status:** Lokal vollständig getestet (Web, Dispatcher, Runner, ZAP, Postgres). Der Cloudflare-Worker wurde lokal in der echten Worker-Laufzeit (`wrangler dev`, workerd) mit Hyperdrive-Simulation und R2 getestet: Login, Dashboard, Ergebnisse, PDF in R2, Cron-Dispatcher. **Nicht getestet:** Container-Betrieb auf Cloudflare (lokal kein Docker) und ein echtes Deployment.
>
> **Einrichtung Schritt für Schritt:** [einrichtung-cloudflare.md](einrichtung-cloudflare.md). Deployment über GitHub Actions (`.github/workflows/cf-deploy.yml`), weil das Runner-Image Docker braucht.

## Ist-Zustand des Cloudflare-Kontos (lesend geprüft am 13.10.2026)

| Ressource | Zustand | Folge |
|---|---|---|
| Worker `web-audit-security` | vorhanden, enthält nur «Hello world» | wird durch dieses Projekt ersetzt (`deploy/cloudflare/wrangler.jsonc`, `name` passt) |
| R2 | **nicht aktiviert** (API: «Please enable R2 through the Cloudflare Dashboard») | Berichtsablage in der Cloud nicht möglich, bis R2 aktiviert ist |
| Hyperdrive | nur `baustellenkontrolle-db` (fremde App) | **nicht wiederverwenden**; eigene Datenbank + eigene Hyperdrive-Konfiguration nötig |
| Workers-Paid-Plan / Containers | über die API nicht feststellbar | Containers setzen den Paid-Plan voraus |

## Zielarchitektur auf Cloudflare

| Komponente | Cloudflare-Dienst | Hinweis |
|---|---|---|
| Web-App | Worker `web-audit-security` mit OpenNext-Adapter (`@opennextjs/cloudflare`) | `nodejs_compat` |
| Datenbank | eigenes Supabase-Projekt via Hyperdrive (Client pro Request, `src/lib/db/index.ts`) | Cloudflare bietet kein verwaltetes Postgres; D1 (SQLite) ist mit dem Schema nicht kompatibel |
| Queue/Dispatcher | Postgres-Queue + Cron-Trigger (jede Minute) im selben Worker | keine Cloudflare Queues nötig |
| Scan-Runner | Cloudflare Containers (`ScanRunnerContainer`, Instanztyp `standard-1`) | Image `deploy/docker/Dockerfile.runner` (ZAP + Node + Repo-Scanner) |
| Berichte | R2-Bucket `web-audit-security-reports` (privat) über R2-Binding `REPORTS` | Zugriff nur über App, keine Zugangsschlüssel |

### Laufzeitlimits (Cloudflare-Doku, Stand 12.10.2026)

- Container-Instanztypen: `lite` (1/16 vCPU, 256 MiB) … `standard-1` (½ vCPU, 4 GiB, 8 GB Disk) … `standard-4` (4 vCPU, 12 GiB, 20 GB). ZAP braucht ≥ 2 GiB → mindestens `standard-1`.
- Image-Grösse ≤ Disk des Instanztyps; das Runner-Image ist ca. 1,5–2 GB.
- Worker-Requests sind für Scans ungeeignet; deshalb läuft der Scan im Container und meldet per Callback.

### Zielkonflikt Egress-Kontrolle in Containers

Cloudflare kann ausgehendes HTTPS **nur mit TLS-Interception** (`interceptHttps`) auf Host-Ebene filtern. Mit Interception sieht der Runner das Cloudflare-Zertifikat statt des Ziel-Zertifikats; die TLS-Prüfpunkte (WA-TLS-*) wären verfälscht. Gewählt ist deshalb: `enableInternet = true`, Schutz anwendungsseitig (Netguard + Egress-Proxy, getestet). Ein netzwerkseitiger Zusatzschutz ist auf Cloudflare damit **nicht** vorhanden. Falls das nicht akzeptabel ist: Runner auf einem VPS mit Firewall betreiben (docker-compose, siehe unten).

## Kostenfaktoren (keine Zusagen, Preise bei Cloudflare prüfen)

- Workers Paid (Grundgebühr pro Monat), nötig für Containers
- Containers: Abrechnung nach aktiver vCPU-Zeit, Arbeitsspeicher, Disk und Egress pro Scan-Minute; ein Basisscan dauert lokal 1–3 Minuten, grosse Websites bis zum Zeitlimit
- R2: Speicher pro GB/Monat und Operationen (Berichte sind klein, typischerweise < 1 MB)
- Hyperdrive: im Workers-Plan enthalten
- Postgres-Anbieter: eigener Tarif (z. B. Supabase/Neon Free- oder Pro-Tarif)
- Optional Anthropic API: pro Token, nur bei aktiv angeforderten KI-Erklärungen

## Schritte bis zum ersten Cloud-Deployment (durch dich bzw. nach deiner Freigabe)

1. **R2 aktivieren** im Cloudflare-Dashboard; Bucket `web-audit-security-reports` anlegen; R2-API-Token (Objekt Lesen/Schreiben, nur dieser Bucket) erstellen.
2. **Postgres** für diese App anlegen (eigenes Projekt). Migrationen ausführen: `DATABASE_URL=… npm run db:migrate`.
3. **Hyperdrive** für diese Datenbank anlegen; ID in `deploy/cloudflare/wrangler.jsonc` eintragen.
4. **Workers Paid** aktivieren (falls nicht vorhanden).
5. Secrets setzen (je `npx wrangler secret put <NAME> -c deploy/cloudflare/wrangler.jsonc`):
   `APP_ENCRYPTION_KEY`, `RUNNER_CALLBACK_SECRET`, `RUNNER_SHARED_SECRET`, `APP_URL`, `S3_ENDPOINT` (`https://<account-id>.r2.cloudflarestorage.com`), `S3_BUCKET`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, optional `ANTHROPIC_API_KEY`.
6. Build: `npm i -D @opennextjs/cloudflare wrangler @cloudflare/containers && npx opennextjs-cloudflare build`
7. Deploy (erst nach deiner ausdrücklichen Freigabe): `npx wrangler deploy -c deploy/cloudflare/wrangler.jsonc`
8. Erstes Konto registrieren, danach `ALLOW_REGISTRATION=false` lassen (ist in `vars` bereits so gesetzt; für die Erstregistrierung kurz auf `true`).

**Nicht verifiziert** sind insbesondere: OpenNext-Kompatibilität aller Seiten, `postgres`-Treiber über Hyperdrive im Worker, Container-Build des Runner-Images, Callback-Erreichbarkeit aus dem Container.

## Alternative: VPS mit docker compose

`deploy/docker/docker-compose.yml`: Postgres, Web, Dispatcher, Runner in getrennten Netzen (Runner hat keine Verbindung zur Datenbank). Zusätzlich auf dem Host eine Egress-Firewall für das Runner-Netz einrichten, z. B. nur TCP 80/443 nach aussen und alle privaten Bereiche (RFC 1918, 100.64/10, 169.254/16, fc00::/7, fe80::/10) sperren. Diese Variante bietet den vollständigen netzwerkseitigen Egress-Schutz.

## Lokale Entwicklung (in Claude Code im Web oder einer anderen Linux-Umgebung)

```bash
npm ci
cp .env.example .env    # Werte setzen (siehe Kommentare)
npm run zap:install     # ZAP 2.17 aus zaproxy/zap-stable extrahieren (Java 17+ nötig)
npm run db:migrate
npm run build && npm start         # Web-App :3000
npm run runner                     # Scan-Runner :8787
npm run worker                     # Dispatcher
npm run testtarget                 # optional: lokales, absichtlich fehlerhaftes Testziel
```
