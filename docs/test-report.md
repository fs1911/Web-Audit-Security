# Testbericht

Ausgeführt am 13.10.2026 in einer Linux-Cloud-Umgebung (Claude Code im Web): Node 22, PostgreSQL 16, OpenJDK 21, OWASP ZAP 2.17.0, gitleaks (go install), osv-scanner 2.7.0, semgrep 1.180.0.

## Automatisierte Tests (`npm test`)

**90 von 90 bestanden** (5 Testdateien):

| Datei | Abgedeckt |
|---|---|
| tests/netguard.test.ts | URL-Validierung, 26 Blockfälle (privat, Loopback, Link-Local, Metadaten, IPv6, IPv4-mapped, NAT64, Dokumentation), alternative IP-Schreibweisen, Produktion ignoriert Test-Ausnahmen, DNS-Mischantworten, **DNS-Rebinding pro Verbindung**, Redirect auf fremde und interne Ziele |
| tests/scope-proxy.test.ts | Scope (keine Subdomain-/Wildcard-Freigabe, Ausschlüsse inkl. Kodierungstricks, zustandsändernde Links), Egress-Proxy (Methoden, Pfade, CONNECT-Ziele, Metadaten, Ports, Request-Budget) |
| tests/redact-crypto.test.ts | Geheimnisbereinigung (Header, Token-Formate, URL-Credentials, Parameter, bekannte Secrets, E-Mails, Strukturen), AES-GCM inkl. Manipulation, Callback-Signaturen inkl. Zeitfenster |
| tests/findings.test.ts | ZAP-Parser (reale Alert-Struktur), Fingerprint/Duplikaterkennung, Scan-Vergleich, native Header-Analyse, Domainverifikation (DNS/Datei/Redirect/intern), Reparaturprompt, Prompt-Injection-Abwehr |
| tests/platform.test.ts | Login-Sperre, Passwortregeln, **Mandantentrennung und Report-Zugriff**, Scan-Freigaben (Berechtigung, Verifikation, aktive Freigabe/Zeitfenster/Produktion/Limits, Parallelität), anonymer und authentifizierter Ablauf, Abbruch, Fehlschlag, Runner ohne ZAP, PDF/JSON-Berichte, Nachprüfung |

Während der Entwicklung durch Tests gefundene und behobene Fehler: «Bearer»-Token im Fliesstext nicht bereinigt; Login-Sperre wirkungslos (E-Mail wurde im Audit-Log überschrieben); fehlende serverseitige Bereinigung hinterlegter Zugangsdaten; Spider las robots.txt-Disallow-Pfade (rief `/danger/` auf); verwaister ZAP-Prozess beim Beenden des Runners; seitenweite Header-Befunde mit Header-Namen als Parameter nicht gruppiert.

## End-to-End-Abnahmetest (`npm run e2e`)

Echte Prozesse: Testziel, Web-App (`next start`), Runner, Dispatcher; echte ZAP-Scans gegen `testtarget` (nur 127.0.0.1). **12 von 12 bestanden:**

```
OK 1 Verifiziertes Testziel hinzufügen | ohne Token: Token in https://127.0.0.1:8443/.well-known/webaudit-verification.txt nicht gefunden; mit Token: Token in https://127.0.0.1:8443/.well-known/webaudit-verification.txt gefunden
OK 2 Echter Basisscan über Worker | Status completed, Werkzeuge {"OWASP ZAP":"2.17.0","WebAudit Native Checks":"0.1.0"}, 2 Methoden
OK 3 Echte Feststellungen mit Nachweisen | 27 Feststellungen (davon 6 aus ZAP), alle mit Nachweis; Beispiel: «Git-Repository-Daten öffentlich abrufbar» – GET https://127.0.0.1:8443/.git/HEAD → Status 200
OK 4 Nicht geprüfte Bereiche ausdrücklich ausgewiesen | 21 geprüft, 0 nicht geprüft/n.a./Fehler; nicht Bestandteil des Modus: WA-AUTH-01, WA-AUTH-02, WA-AUTH-03, WA-ACT-01, WA-REPO-01, WA-REPO-02, WA-REPO-03, WA-MAN-01, WA-MAN-02, WA-MAN-03, WA-MAN-04, WA-MAN-05, WA-MAN-06
OK 5 PDF- und JSON-Bericht | PDF 32190 Byte, JSON 27 Feststellungen; Download Eigentümer 200, fremde Org 404, anonym 401
OK B Authentifizierter Scan (Testrolle getrennt) | Status completed; 33 Feststellungen; geschützte Seiten abgerufen: 2; «Sitzung bleibt nach Logout gültig (Admin-Test)»
OK 9 Zugangsdaten nicht in Reports/Logs | Testtoken in DB-Ergebnistabellen, Berichten und Prozess-Logs gefunden: 0×
OK 8 Scan-Abbruch | Status cancelled nach 6 s (Phase beim Abbruch: Spider: Seiten im Scope erfassen); verbleibende ZAP-Prozesse: keine; übernommene Teilergebnisse: 0
OK 6 Wiederholungsscan vergleichbar | Vorscan f9a0900c; neu 5, behoben 19, unverändert 8, nicht erneut geprüft 0; Nachprüfungsvermerk an 19 alten Feststellungen
OK 7 Interne/nicht freigegebene Ziele blockiert | 6/6 interne URLs abgelehnt; fremde Hosts ausserhalb Scope: true; unverifizierte Website: «Kein Host dieser Website ist technisch verifiziert.»; verbotene Aufrufe am Testziel (Formular-POST, /danger/*): keine
OK 10 Ehrliche Fehlermeldung bei fehlender Infrastruktur | ohne ZAP: «Scan nicht gestartet: OWASP ZAP nicht gefunden (ZAP_HOME_DIR=/nicht/vorhanden). Installation: npm run zap:install. Es wurden keine Ergebnisse erzeugt.»; ohne Runner: «Scan-Worker nicht erreichbar (http://127.0.0.1:8788). Es wurden keine Ergebnisse erzeugt.»
OK Callback-Schutz | gefälschter Runner-Callback → HTTP 401
```

Erzeugte Beispielberichte (nur lokale Testdaten): [docs/examples](examples/). Screenshots der Oberfläche mit diesen Daten: [docs/screenshots](screenshots/).

## Weitere manuell ausgeführte Läufe

- **Modus C (aktiv)** gegen testtarget: abgeschlossen, 12 Regeln des Profils webaudit-safe, keine verbotenen Aufrufe am Testziel.
- **Modus D (Repository)** gegen dieses Repository (Commit 8eb40f5): Klon und gitleaks/semgrep erfolgreich (Treffer = absichtliche Test-Fixtures bzw. bewusst deaktivierte Zertifikatsprüfung in `inspectTls`). osv-scanner: **Fehler**, weil api.osv.dev in der Testumgebung durch die Egress-Richtlinie blockiert ist (403) – korrekt als «Fehler» in der Abdeckung ausgewiesen.

## Nicht getestet

- Cloudflare-Deployment (OpenNext, Hyperdrive, Containers, R2) – nicht deployt.
- KI-Erklärung gegen die echte Anthropic-API (kein Schlüssel vorhanden).
- Scans gegen reale externe Websites (bewusst nicht ausgeführt; kein freigegebenes Ziel).
- Docker-Images (kein Docker-Daemon in der Testumgebung).
