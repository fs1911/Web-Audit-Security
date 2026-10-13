# Tatsächliche Funktionsgrenzen

Diese Liste ist verbindlich. Was hier steht, kann die Plattform **nicht** oder **nur teilweise**.

## Grundsätzlich

- Automatisierte technische Prüfung im angegebenen Umfang. **Kein** vollständiger Penetrationstest, **keine** ISO-Zertifizierung, **kein** Nachweis rechtlicher oder datenschutzrechtlicher Konformität, **keine** ASVS-Level-Erfüllung.
- «Keine Feststellung» heisst nur: im geprüften Umfang mit den ausgeführten Werkzeugen nichts erkannt.
- Manuelle Prüfbereiche (Zugriffskontrolle/Rollenmodell, Business-Logik, Authentifizierungsverfahren, CSRF, Logging/Alerting, Datenschutz) sind im Katalog als «nicht implementiert / manuell» geführt.

## Modus A – Basischeck

- Spider ohne JavaScript-Ausführung (kein AJAX-Spider): Inhalte, die nur per JavaScript geladen werden, werden nicht erfasst.
- Native Header-/Cookie-Analyse nur auf der Startseite; weitere Seiten über ZAP-Regeln.
- TLS: nur die mit einem modernen Client ausgehandelte Version; ob TLS 1.0/1.1 zusätzlich akzeptiert werden, wird nicht geprüft. Keine OCSP-/Sperrlistenprüfung.
- HTTP→HTTPS-Prüfung nur bei HTTPS auf Port 443 (bzw. lokal mit `WEBAUDIT_HTTP_PROBE_PORT`).
- Mixed Content: statische HTML-Analyse der Startseite plus ZAP-Regel 10040; dynamisch nachgeladene Ressourcen nicht.
- CORS: nur Beobachtung einer GET-Antwort mit fremdem Origin; keine Preflight-Analyse.
- Passiv ist nicht zugriffsfrei: Der Spider erzeugt Anfragen und Logeinträge.

## Modus B – Authentifiziert

- Nur Sitzungs-Header oder Sitzungs-Cookie eines Testkontos. **Formularbasierte Anmeldung (Benutzername/Passwort) ist nicht implementiert.**
- Sitzungsprüfung vergleicht Statuscode und Antwortlänge mit/ohne Zugang (Heuristik).
- Logout-Prüfung ruft die Logout-URL per GET auf; Logouts, die POST erfordern, werden nicht geprüft.
- Rollen werden getrennt gescannt; **Berechtigungsprüfungen zwischen Rollen (wer darf was) werden nicht automatisch abgeleitet.**

## Modus C – Aktiv

- Nur das feste ZAP-Profil «webaudit-safe» (12 Regeln in ZAP 2.17.0: 0, 6, 10045, 10058, 20019, 40003, 40008, 40012, 40028, 40029, 40032, 40035; Regel 10095 ist in dieser ZAP-Version nicht vorhanden). Schreibwirkende Regeln (SQLi-Varianten, persistentes XSS, SSI) nur mit gesonderter Freigabe und nie auf Produktion.
- Über HTTPS kann der Egress-Proxy Methoden/Pfade nicht sehen; die Begrenzung erfolgt durch ZAP-Konfiguration.
- Standardmässig deaktiviert (`ENABLE_ACTIVE_SCANS=false`).

## Modus D – Repository

- Nur `https://github.com/<owner>/<repo>`; Klontiefe 100 Commits (ältere Historie wird von gitleaks nicht gesehen).
- osv-scanner benötigt Lockfiles und übermittelt Paketnamen/-versionen an osv.dev.
- Semgrep nutzt standardmässig nur den kleinen eigenen Regelsatz (9 Regeln). Ergebnisse sind Verdachtsfälle.
- Keine automatischen Änderungen oder Commits (bewusst nicht implementiert).

## Plattform

- API-Spezifikation wird gespeichert, aber **kein API-Scan** auf Basis von OpenAPI ausgeführt.
- Netzwerkseitiger Egress-Schutz (Firewall) ist **nicht** Teil des Codes und muss beim Hosting eingerichtet werden; auf Cloudflare Containers wird er aus TLS-Gründen nicht genutzt (siehe deployment.md).
- Cloudflare-Deployment: Worker lokal in workerd getestet; Container-Betrieb und echtes Deployment **nicht** getestet. Next.js ist auf 15.x fixiert, weil OpenNext 1.20 mit Next 16.4 nicht funktioniert (geprüft: «Unexpected loadManifest(preview-props.json)»). TypeScript auf 5.9 fixiert (Next 15 ist mit TypeScript 7 inkompatibel).
- Scan-Abbruch auf Cloudflare wirkt über die Callback-Antwort an den Runner (Herzschlag alle 5 s), nicht über einen direkten Aufruf.
- Mehrere Organisationen pro Konto: Datenmodell unterstützt es; die UI bietet derzeit keine Einladungs- und Wechselfunktion (Mitglieder werden über die Datenbank verwaltet).
- E-Mail-Benachrichtigungen, Passwort-Zurücksetzen und MFA für Plattformkonten: nicht implementiert.
- Aufbewahrung/Löschung: Skript vorhanden (`npm run retention`), muss per Cron eingeplant werden.
- KI-Erklärung: implementiert, in dieser Session **nicht** gegen die echte Anthropic-API getestet (kein Schlüssel); Validierung und Injection-Abwehr sind mit Unit-Tests geprüft.
- PDF nutzt Standardschriften (WinAnsi); Zeichen ausserhalb dieses Zeichensatzes werden ersetzt.
