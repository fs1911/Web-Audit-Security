# WebAudit Security

Browserbasierte Plattform zur **technischen Sicherheitsprüfung eigener Websites** im ausdrücklich freigegebenen Umfang. Deutsche Oberfläche (Schweizer Schreibweise). Technik: Next.js 15, PostgreSQL, OWASP ZAP 2.17, Cloudflare Workers + Containers.

> Automatisierte technische Sicherheitsprüfung im angegebenen Umfang. Kein vollständiger Penetrationstest, keine ISO-Zertifizierung und kein Nachweis der vollständigen rechtlichen oder datenschutzrechtlichen Konformität.

## Was die Plattform tut

1. Website mit URL, Umgebung, verantwortlicher Person, erlaubten/ausgeschlossenen Pfaden und weiteren Hosts erfassen.
2. Prüfberechtigung bestätigen (mit Audit-Log) und **jeden Host technisch verifizieren** (DNS-TXT oder Challenge-Datei).
3. Prüfmodus wählen und Umfang/Limits vor dem Start bestätigen:
   - **A – Schonender Basischeck**: TLS, HTTP→HTTPS, Sicherheits-Header, Cookies, Mixed Content, `.git`-Exposition, security.txt, OWASP-ZAP-Spider (ohne Formulare) + passive ZAP-Regeln
   - **B – Authentifiziert**: wie A je Testrolle getrennt, plus Sitzungs- und Logout-Prüfung
   - **C – Aktiv** (standardmässig aus): festes ZAP-Profil «webaudit-safe», nur mit Freigabe (Ziel, Zeitfenster, Limits)
   - **D – Repository**: gitleaks, osv-scanner, semgrep auf festem Commit
4. Echter Scan über einen separaten Runner mit **OWASP ZAP 2.17**; Fortschritt, Phase, Abbruch.
5. Ergebnisse: Management-Zusammenfassung, technische Details, Filter, getrennte Anzeige von Sicherheitslücken / Konfigurationshinweisen / Verdachtsfällen, Prüfabdeckung.
6. Pro Feststellung ein **kopierfertiger Claude-Code-Reparaturprompt** (deterministisch, ohne KI) und optional eine KI-Erklärung.
7. **PDF- und JSON-Berichte**, Wiederholungsscan mit **Vergleich** (neu / behoben / unverändert / nicht erneut geprüft).

## Schnellstart (Claude Code im Web oder jede Linux-Umgebung, keine lokale Installation auf deinem Rechner nötig)

Voraussetzungen in der Umgebung: Node.js 22, PostgreSQL 16, Java 17+ (für ZAP). Alles Weitere installiert das Projekt.

```bash
npm ci
cp .env.example .env        # Schlüssel erzeugen, siehe Kommentare in .env.example
npm run zap:install         # OWASP ZAP 2.17 nach /opt/zap (aus dem offiziellen Image zaproxy/zap-stable)
npm run db:migrate
npm run build
npm start                   # Web-App auf :3000
npm run runner              # Scan-Runner auf :8787 (separater Prozess)
npm run worker              # Dispatcher (Queue → Runner)
```

Dann im Browser `/register` öffnen, Konto + Organisation anlegen, Website hinzufügen, Host verifizieren, Scan starten.

### Ausprobieren ohne fremde Website

`npm run testtarget` startet eine **nur lokal** erreichbare Testanwendung mit absichtlichen Fehlkonfigurationen (https://127.0.0.1:8443). Damit sie trotz SSRF-Schutz geprüft werden kann, in `.env` (nur ausserhalb von production wirksam):

```
NETGUARD_TEST_ALLOW_CIDRS=127.0.0.1/32
NETGUARD_TEST_ALLOW_PORTS=8081,8443
WEBAUDIT_ALLOW_INVALID_CERTS=true
WEBAUDIT_HTTP_PROBE_PORT=8081
```

`TESTTARGET_FIXED=1 npm run testtarget` liefert die «behobene» Variante für einen Vergleichsscan.

## Tests

```bash
npm test          # Unit- und Integrationstests (Postgres-Testdatenbank webaudit_test)
npm run e2e       # Vollständiger Abnahmetest: echte ZAP-Scans gegen das lokale Testziel
npm run typecheck
```

## Dokumentation

| Dokument | Inhalt |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Komponenten, Ablauf, Datenmodell, KI-Rolle |
| [docs/threat-model.md](docs/threat-model.md) | Bedrohungsmodell (STRIDE) mit Umsetzungsstatus |
| [docs/catalog.md](docs/catalog.md) | Prüfkatalog, Referenzwerke, Lizenzen |
| [docs/coverage-matrix.md](docs/coverage-matrix.md) | Coverage-Matrix (generiert) |
| [docs/einrichtung-cloudflare.md](docs/einrichtung-cloudflare.md) | **Schritt-für-Schritt-Einrichtung auf Cloudflare + Supabase (nur Browser)** |
| [docs/deployment.md](docs/deployment.md) | Cloudflare-Architektur, Kosten, VPS-Alternative |
| [docs/limitations.md](docs/limitations.md) | Tatsächliche Funktionsgrenzen |
| [docs/test-report.md](docs/test-report.md) | Zuletzt ausgeführte Tests und Ergebnisse |

## Sicherheitsgrundsätze

- Scans nur auf verifizierte Hosts im Scope; keine Wildcards, keine automatische Subdomain-Freigabe.
- SSRF-Schutz: nur öffentliche Ziele, DNS-Prüfung bei jedem Verbindungsaufbau, Redirect-Prüfung, ZAP nur über einen prüfenden Egress-Proxy.
- Zugangsdaten AES-256-GCM-verschlüsselt; Bereinigung in Runner **und** Web-App; Berichte nur über berechtigten Download.
- Die Plattform verändert geprüfte Websites und Repositories nie selbst.
- Ohne vorhandene Werkzeuge (z. B. ZAP) schlägt ein Scan mit klarer Meldung fehl – es werden nie Ergebnisse simuliert.
