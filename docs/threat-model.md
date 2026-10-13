# Bedrohungsmodell

Methode: STRIDE pro Vertrauensgrenze. Status: **umgesetzt** (mit Test), **teilweise**, **offen**.

## Vertrauensgrenzen

1. Browser ↔ Web-App
2. Web-App ↔ Datenbank / Objektspeicher
3. Dispatcher ↔ Runner (Job-Übergabe)
4. Runner ↔ Web-App (Callbacks)
5. Runner/ZAP ↔ Internet (geprüfte Ziele) – **Ziele und deren Antworten sind nicht vertrauenswürdig**
6. Web-App ↔ externe KI (optional)

## Bedrohungen und Massnahmen

| # | Bedrohung | Massnahme | Status |
|---|---|---|---|
| T1 | Plattform wird als frei zugänglicher Angriffsscanner missbraucht | Anmeldung, RBAC, Bestätigung der Prüfberechtigung, technische Domainverifikation je Host, keine Wildcards/Subdomain-Freigabe, Limits, Audit-Log, aktive Prüfungen nur mit Feature-Flag + zeitlich begrenzter Freigabe | umgesetzt (tests/platform.test.ts) |
| T2 | SSRF auf interne Netze/Cloud-Metadaten (auch via alternative IP-Schreibweisen, IPv6, IPv4-mapped, NAT64) | `validateUrl` + `classifyIp` (Allowlist-Ansatz, IANA-Spezialbereiche) | umgesetzt (tests/netguard.test.ts) |
| T3 | DNS-Rebinding zwischen Prüfung und Verbindung | `guardedLookup` prüft bei JEDEM Socket-Aufbau und verbindet auf die geprüfte IP; Egress-Proxy verbindet auf geprüfte IP | umgesetzt (Test «Rebinding») |
| T4 | Umgehung über Redirects | Redirects manuell, pro Hop Scope + Netguard | umgesetzt |
| T5 | Umgehung durch ZAP/Unterprozesse | ZAP nur über Egress-Proxy (Upstream-Proxy, verifiziert vor Scanstart, sonst Abbruch); Host-Proxy-Variablen entfernt; Proxy prüft Host, Port, IP, Budget, bei HTTP auch Pfad/Methode | umgesetzt |
| T5a | ZAP öffnet direkte Verbindungen trotz Proxy-Einstellung (z. B. Add-on-Fehler) | Netzwerkseitige Durchsetzung nötig: Container-Firewall/Netzwerkrichtlinie (nur 80/443, keine privaten Netze). In docker-compose nur dokumentiert; in Cloudflare siehe Zielkonflikt TLS-Interception | **teilweise** |
| T5b | Pfad-/Methodenkontrolle innerhalb von HTTPS-Tunneln | Nur über ZAP-Konfiguration (Kontext-Ausschlüsse, Spider ohne Formulare, Standardausschlüsse für logout/delete/…). Proxy sieht in TLS nur Host/Port | **teilweise** (bewusst, dokumentiert) |
| T6 | Zustandsändernde Aktionen beim passiven Scan | Kein Formularversand, keine robots.txt-Disallow-Liste als Linkquelle, Standardausschlüsse, GET/HEAD-Allowlist am Proxy | umgesetzt (E2E: Testziel protokolliert verbotene Aufrufe) |
| T7 | Mandantenleck | Jeder Zugriff über `requireSite/requireScan/requireFinding/requireReport` mit Org-Prüfung; einheitliche «kein Zugriff»-Antwort | umgesetzt (Tests + E2E-Download) |
| T8 | Report-Abfluss | Objektspeicher privat; Download nur über App mit Berechtigungsprüfung, `no-store`; Download im Audit-Log | umgesetzt |
| T9 | Secrets in Logs/Reports/DB | AES-256-GCM für Zugangsdaten; Klartext nur im Runner-Speicher; `redact()` an Runner UND Web-App (inkl. hinterlegter Werte des Scans); Token via Git-Umgebung statt argv | umgesetzt (E2E prüft DB, Berichte, Prozess-Logs) |
| T10 | Gefälschte Runner-Callbacks | HMAC je Job, Zeitfenster 5 min, konstantzeitiger Vergleich | umgesetzt |
| T11 | Kompromittierter Runner | Keine DB-Zugangsdaten, nur eigenes Job-Token; ZAP-API nur 127.0.0.1 mit Zufallsschlüssel; Prozess ohne Shell | teilweise (Container-Härtung abhängig vom Hosting) |
| T12 | Prompt Injection über gescannte Inhalte | KI nur optional; Daten in markiertem Block, Tag-Neutralisierung; Ausgabeprüfung gegen nicht belegte URLs/CVEs/Sicherheitszusagen; KI hat keine Werkzeuge; Scope/Freigaben deterministisch ausserhalb der KI; Reparaturprompts kennzeichnen Nachweise als nicht vertrauenswürdig | umgesetzt (tests/findings.test.ts) |
| T13 | Command Injection über Repo-URL/Ref | Nur `https://github.com/<owner>/<repo>`, Ref-Format geprüft, `--` vor URL, keine Shell | umgesetzt |
| T14 | Brute Force auf Login | 5 Fehlversuche / 15 min pro E-Mail-Hash; argon2id | umgesetzt |
| T15 | CSRF | Server Actions (Origin-Prüfung durch Next.js), SameSite=Lax-Cookies | umgesetzt (framework-seitig) |
| T16 | Überlastung des Ziels | Request-Budget + Rate-Limit am Proxy und in ZAP, Threads begrenzt, Zeitlimit, ein Scan pro Website | umgesetzt |
| T17 | Übermässige Datenhaltung | Bereinigte, gekürzte Nachweise; konfigurierbare Aufbewahrung (`npm run retention`) | umgesetzt (Cron muss eingerichtet werden) |

## Restrisiken

- **Netzwerkseitiger Egress-Schutz** ist lokal nicht vorhanden (Sandbox ohne Firewall-Rechte) und muss beim Hosting eingerichtet werden. Der anwendungsseitige Schutz ist getestet.
- **DNS-TXT-Verifikation** vertraut dem DNS-Resolver des Servers.
- **Freigaben** sind Selbsterklärungen der Nutzenden; die Plattform kann rechtliche Berechtigung nicht beweisen, nur technisch die Kontrolle über Host bzw. DNS.
