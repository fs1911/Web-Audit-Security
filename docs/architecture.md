# Architektur

## Überblick

```
 Browser ──HTTPS──► Web-App (Next.js 16, App Router, TypeScript)
                     │   Anmeldung, RBAC, Mandanten, Websites, Freigaben, Ergebnisse, Berichte
                     │
                     ├──► PostgreSQL (Drizzle ORM, Migrationen in drizzle/)
                     │      users, organizations, memberships, sites, site_hosts, credentials (AES-GCM),
                     │      scan_approvals, scans, scan_jobs (Queue), findings, coverage_results,
                     │      reports, scan_events, audit_log
                     │
                     └──► Objektspeicher (privat): lokal «fs» oder S3-kompatibel (Cloudflare R2)

 Dispatcher (eigener Prozess / Cloudflare Cron)
   claimNextJob(): UPDATE … FOR UPDATE SKIP LOCKED  →  POST /jobs an Runner (Bearer RUNNER_SHARED_SECRET)

 Scan-Runner (eigener Prozess/Container, KEINE DB-Zugangsdaten)
   ├─ Netguard: URL-/IP-Prüfung, DNS-Prüfung bei jedem Verbindungsaufbau, Redirect-Prüfung
   ├─ Native Checks: TLS, HTTP→HTTPS, Header, Cookies, Mixed Content, /.git/HEAD, security.txt
   ├─ Egress-Proxy (127.0.0.1, zufälliger Port) ◄── einziger Netzweg für ZAP
   ├─ OWASP ZAP 2.17 (Daemon pro Scan, eigener API-Key, eigenes Home, ohne Host-Proxy-Variablen)
   │     Spider (ohne Formulare, ohne robots.txt-Disallow-Liste) → passive Regeln → optional aktives Profil
   └─ Repository-Adapter: gitleaks, osv-scanner, semgrep (fester Commit, nur Lesen)
        │
        └──► signierte Callbacks  POST /api/internal/jobs/:jobId/events
             (HMAC-SHA256 mit job-spezifischem Token = HMAC(RUNNER_CALLBACK_SECRET, jobId), ±5 min)
             Antwort {cancel:true} ⇒ Runner bricht ab
```

## Warum diese Aufteilung

- **Langlaufende Scans nie im Web-Request.** Der Web-Request legt nur `scans` + `scan_jobs` an. Der Dispatcher übergibt an den Runner, der asynchron arbeitet.
- **Runner ohne Datenbankzugang.** Ein kompromittierter Scanner-Prozess (z. B. über eine bösartige Zielantwort) kann keine fremden Mandantendaten lesen. Er kennt nur seine eigene Job-Spezifikation und ein job-spezifisches Callback-Token.
- **Queue in Postgres.** Kein zusätzlicher Dienst (Redis) nötig; `SKIP LOCKED` erlaubt mehrere Dispatcher.
- **ZAP als Daemon pro Scan**, gesteuert über die REST-API (statt `zap-baseline.py`, das ein Docker-Image voraussetzt). Konfiguration ist im Code nachvollziehbar (`src/runner/zap/scan.ts`). Das Automation-Framework-Add-on ist in der Distribution enthalten, wird aber derzeit nicht genutzt, weil die API eine feinere Abbruch- und Fortschrittssteuerung erlaubt.

## Ablauf eines Scans

1. **Start** (`startScan`, `src/lib/scans/service.ts`) prüft deterministisch: Bestätigung von Umfang/Limits, Prüfberechtigung der Website, verifizierter Host der Basis-URL, Scope-Konformität, Parallelitätslimits, bei Modus C Feature-Flag, gültige Freigabe im Zeitfenster, Ziel = Freigabe-Ziel, nicht Produktion (ausser explizit erlaubt), Freigabe-Limits als Obergrenze. Jeder abgelehnte Start wird im Audit-Log festgehalten.
2. **Scope-Snapshot**: nur einzeln verifizierte Hosts, Pfade und Ausschlüsse werden beim Start eingefroren.
3. **Dispatcher** baut die Job-Spezifikation (inkl. entschlüsselter Testzugänge, nur im Speicher) und übergibt sie.
4. **Runner** prüft erneut (Defense in Depth), führt Werkzeuge aus, sendet Fortschritt (`progress`), Herzschlag (`heartbeat`), `results` und `complete`/`failed`.
5. **Web-App** bereinigt erneut (inkl. der hinterlegten Zugangsdaten dieses Scans), dedupliziert, schreibt Feststellungen und Abdeckung. Nicht gemeldete Prüfpunkte des Modus werden ausdrücklich als «nicht geprüft» gespeichert.
6. **Nachprüfung**: nach Abschluss werden Feststellungen des Vorscans (gleiche Website, gleicher Modus) per Fingerprint abgeglichen (`applyRetest`).

## Abbruch und Zeitlimits

- Nutzer klickt «Abbrechen» → `cancel_requested` + direkter `POST /jobs/:id/cancel` an den Runner; zusätzlich antwortet jeder Callback mit `cancel:true`.
- Runner: `AbortController` stoppt Spider/Active Scan über die ZAP-API, beendet die ZAP-Prozessgruppe (`SIGKILL` auf die Gruppe), schliesst den Egress-Proxy.
- Teilergebnisse abgebrochener oder fehlgeschlagener Scans werden verworfen.
- Dispatcher beendet Scans ohne Herzschlag nach 3 Minuten als «fehlgeschlagen» und fordert bei Überschreitung von `maxDurationMinutes + 10` den Abbruch an.

## Datenmodell (Kurzfassung)

Siehe `src/lib/db/schema.ts`. Wesentlich:
- Schweregrad (`severity`) und Vertrauen (`confidence`) sind getrennte Felder.
- `kind`: `vulnerability` | `configuration` | `suspicion` | `informational` – die UI trennt diese Gruppen.
- CVSS-Felder sind nur gesetzt, wenn eine Quelle (z. B. OSV) einen Vektor liefert; die Plattform berechnet keine CVSS-Werte.
- `references` speichert Zuordnungen mit `verified`-Flag.

## KI-Komponente

`src/lib/ai/explain.ts`: optional, standardmässig aus, pro Organisation abschaltbar. Erhält nur bereinigte Felder einer bestehenden Feststellung in einem als nicht vertrauenswürdig markierten Block. Keine Tools, kein Netz, keine Secrets. Ausgabe wird schema-validiert und verworfen, wenn sie nicht belegte URLs/CVEs, Sicherheitszusagen oder aktive Inhalte enthält. Scans, Berichte und Reparaturprompts funktionieren ohne KI.

## Laufzeitlimits der Zielplattform (Cloudflare)

Geprüft in der Cloudflare-Dokumentation (Stand 12.10.2026): Workers eignen sich für die Web-App, nicht für ZAP (Java, minutenlange Laufzeit). Der Runner benötigt **Cloudflare Containers** (Instanztyp `standard-1`: ½ vCPU, 4 GiB RAM, 8 GB Disk). Details und Kosten: [deployment.md](deployment.md).
