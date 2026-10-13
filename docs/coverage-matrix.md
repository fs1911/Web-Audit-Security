# Coverage-Matrix (Prüfkatalog 2026.10.0)

> Automatisch erzeugt mit `npm run catalog:matrix` aus `catalog/checks.json`. Nicht von Hand bearbeiten.
>
> «Geprüft / nicht geprüft / nicht anwendbar» und der **Nachweis** sind Eigenschaften eines konkreten Scans und stehen in der Abdeckung jedes Scans (UI, PDF- und JSON-Bericht). Diese Matrix beschreibt, was die Plattform prüfen *kann*.
>
> Ein URL-Scan belegt **keine** vollständige ASVS-Level-Erfüllung, keine ISO-Konformität und keine Datenschutzkonformität.

## Referenzwerke

| Referenz | Version | Quelle | Übernommen | Lizenz |
|---|---|---|---|---|
| OWASP Application Security Verification Standard | 5.0.0 | https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en | 2026-10-13 | CC BY-SA 4.0 (Creative Commons Attribution-ShareAlike 4.0) |
| OWASP Web Security Testing Guide | 4.2 | https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing | 2026-10-13 | CC BY-SA 4.0 |
| OWASP Top 10 | 2025 | https://owasp.org/Top10/2025/ | 2026-10-13 | CC BY-SA 4.0 |
| Common Weakness Enumeration | 4.20 | https://cwe.mitre.org/ | 2026-10-13 | CWE Terms of Use (MITRE, frei nutzbar mit Quellenangabe) |
| Common Vulnerability Scoring System | 4.0 | https://www.first.org/cvss/v4.0/specification-document | 2026-10-13 | FIRST CVSS Terms of Use |
| ISO/IEC 27002:2022 (Zuordnung) | 2022 | https://www.iso.org/standard/75652.html | 2026-10-13 | Urheberrechtlich geschützt (ISO). Keine Normtexte übernommen. |

## Prüfpunkte

| ID | Anforderung/Test | Referenz und Version | Benötigte Eingaben | Prüfmethode | Automatisierung | Implementiert | Modi | Einschränkungen |
|---|---|---|---|---|---|---|---|---|
| WA-TLS-01 | HTTPS erreichbar und Zertifikat vertrauenswürdig | ASVS 5.0.0 12.2.2<br>WSTG 4.2 WSTG-CRYP-01<br>OWASP-TOP10 2025 A04:2025<br>CWE 4.20 CWE-295<br>ISO27002 2022 8.24 (unverifiziert) | Basis-URL | native:tls | Automatisch | ja | A, B, C | Prüft die Zertifikatskette gegen den Node.js-Trust-Store. Keine Prüfung von Sperrlisten/OCSP. |
| WA-TLS-02 | Ausgehandelte TLS-Version | ASVS 5.0.0 12.1.1<br>WSTG 4.2 WSTG-CRYP-01<br>CWE 4.20 CWE-326 | Basis-URL | native:tls | Teilweise automatisch | ja | A, B, C | Ermittelt nur die mit einem modernen Client ausgehandelte Version. Ob veraltete Versionen (TLS 1.0/1.1) zusätzlich akzeptiert werden, wird NICHT geprüft. |
| WA-TLS-03 | Restlaufzeit des Zertifikats | WSTG 4.2 WSTG-CRYP-01<br>CWE 4.20 CWE-298 | Basis-URL | native:tls | Automatisch | ja | A, B, C | Warnschwelle 30 Tage. |
| WA-HTTP-01 | Weiterleitung von HTTP auf HTTPS | ASVS 5.0.0 12.2.1<br>WSTG 4.2 WSTG-CRYP-03<br>OWASP-TOP10 2025 A04:2025<br>CWE 4.20 CWE-319 | Basis-URL | native:http | Automatisch | ja | A, B, C | Geprüft wird nur die Startseite über Port 80. |
| WA-HDR-01 | HTTP Strict Transport Security (HSTS) | ASVS 5.0.0 3.4.1<br>WSTG 4.2 WSTG-CONF-07<br>OWASP-TOP10 2025 A02:2025<br>CWE 4.20 CWE-319 | Basis-URL | native:headers | Automatisch | ja | A, B, C | Geprüft auf der Startseite und den nativ abgerufenen Seiten; ZAP prüft zusätzlich gecrawlte Seiten. |
| WA-HDR-02 | Content Security Policy | ASVS 5.0.0 3.4.3<br>OWASP-TOP10 2025 A02:2025<br>CWE 4.20 CWE-693 | Basis-URL | native:headers | Teilweise automatisch | ja | A, B, C | Prüft Vorhandensein sowie object-src und base-uri. Die Wirksamkeit der Policy im Detail wird nicht bewertet. |
| WA-HDR-03 | X-Content-Type-Options: nosniff | ASVS 5.0.0 3.4.4<br>CWE 4.20 CWE-693 | Basis-URL | native:headers | Automatisch | ja | A, B, C | – |
| WA-HDR-04 | Referrer-Policy | ASVS 5.0.0 3.4.5<br>CWE 4.20 CWE-200 | Basis-URL | native:headers | Automatisch | ja | A, B, C | Browser-Standardverhalten (strict-origin-when-cross-origin) wird als ausreichend gewertet, aber als Hinweis ausgewiesen. |
| WA-HDR-05 | Schutz vor Clickjacking (frame-ancestors) | ASVS 5.0.0 3.4.6<br>WSTG 4.2 WSTG-CLNT-09<br>CWE 4.20 CWE-1021 | Basis-URL | native:headers | Automatisch | ja | A, B, C | X-Frame-Options wird als Ersatz erkannt, aber gemäss ASVS als veraltet gekennzeichnet. |
| WA-HDR-06 | Versionsangaben in Server-Headern | ASVS 5.0.0 13.4.6<br>WSTG 4.2 WSTG-INFO-02<br>CWE 4.20 CWE-200 | Basis-URL | native:headers | Automatisch | ja | A, B, C | Nur Server- und X-Powered-By-Header. |
| WA-HDR-07 | CORS: Wildcard mit Credentials | ASVS 5.0.0 3.4.2<br>WSTG 4.2 WSTG-CLNT-07<br>CWE 4.20 CWE-942 | Basis-URL | native:headers | Teilweise automatisch | ja | A, B, C | Beobachtet nur Antworten auf normale GET-Anfragen mit fremdem Origin-Header; keine Preflight-Prüfung. |
| WA-HDR-08 | Cross-Origin-Opener-Policy | ASVS 5.0.0 3.4.8 | Basis-URL | native:headers | Automatisch | ja | A, B, C | ASVS Level 3; wird als Information ausgewiesen. |
| WA-CK-01 | Cookie-Attribut Secure | ASVS 5.0.0 3.3.1<br>WSTG 4.2 WSTG-SESS-02<br>CWE 4.20 CWE-614 | Basis-URL | native:cookies | Automatisch | ja | A, B, C | Nur Cookies, die auf den nativ abgerufenen Seiten gesetzt werden; ZAP ergänzt gecrawlte Seiten. |
| WA-CK-02 | Cookie-Attribut HttpOnly | ASVS 5.0.0 3.3.4<br>WSTG 4.2 WSTG-SESS-02<br>CWE 4.20 CWE-1004 | Basis-URL | native:cookies | Teilweise automatisch | ja | A, B, C | Ob ein Cookie von Skripten gelesen werden muss, kann nicht automatisch beurteilt werden. |
| WA-CK-03 | Cookie-Attribut SameSite | ASVS 5.0.0 3.3.2<br>WSTG 4.2 WSTG-SESS-02<br>CWE 4.20 CWE-1275 | Basis-URL | native:cookies | Teilweise automatisch | ja | A, B, C | Zweckgerechte Wahl des Werts nicht automatisch beurteilbar. |
| WA-CK-04 | Cookie-Präfix __Host-/__Secure- | ASVS 5.0.0 3.3.3 | Basis-URL | native:cookies | Automatisch | ja | A, B, C | Information; ob ein Cookie hostübergreifend geteilt werden muss, ist nicht automatisch beurteilbar. |
| WA-MC-01 | Gemischte Inhalte (Mixed Content) | WSTG 4.2 WSTG-CRYP-03<br>CWE 4.20 CWE-319 | Basis-URL | native:html | Teilweise automatisch | ja | A, B, C | Statische Analyse des HTML der nativ abgerufenen Seiten; dynamisch per JavaScript nachgeladene Ressourcen werden nicht erkannt. Keine direkte ASVS-5.0-Anforderung. |
| WA-CFG-01 | Öffentlich erreichbare Versionsverwaltungsdaten (.git) | ASVS 5.0.0 13.4.1<br>WSTG 4.2 WSTG-CONF-04<br>CWE 4.20 CWE-527 | Basis-URL | native:probe | Automatisch | ja | A, B, C | Eine einzelne GET-Anfrage auf /.git/HEAD; andere Versionsverwaltungen nicht geprüft. |
| WA-CFG-02 | security.txt vorhanden | – | Basis-URL | native:probe | Automatisch | ja | A, B, C | Information (RFC 9116), keine Sicherheitslücke. |
| WA-CRAWL-01 | Erfassung öffentlich erreichbarer Seiten im Scope | WSTG 4.2 WSTG-INFO-07 | Basis-URL, Scope | zap:spider | Automatisch | ja | A, B, C | Klassischer Spider ohne JavaScript-Ausführung; Formulare werden nicht abgesendet; Request-Limit und Zeitlimit begrenzen die Abdeckung. |
| WA-ZAP-PASSIVE | Passive ZAP-Regeln auf gecrawlten Antworten | WSTG 4.2 WSTG-INFO-05 | Basis-URL, Scope | zap:pscan | Automatisch | ja | A, B, C | Regelbezogene CWE/WASC-Zuordnungen stammen aus ZAP. Passive Regeln erzeugen teilweise Fehlalarme. |
| WA-AUTH-01 | Testsitzung gültig und von anonymem Zugriff unterscheidbar | WSTG 4.2 WSTG-SESS-01 | Testzugang (Header/Cookie), Prüf-URL | native:auth | Teilweise automatisch | ja | B | Eine unterschiedliche Antwort belegt nicht, dass Berechtigungen korrekt umgesetzt sind. |
| WA-AUTH-02 | Logout beendet die Sitzung serverseitig | WSTG 4.2 WSTG-SESS-06<br>CWE 4.20 CWE-613 | Testzugang, Prüf-URL, Logout-URL | native:auth | Teilweise automatisch | ja | B | Nur wenn Logout-URL angegeben; ruft den Logout per GET auf. Nur mit separaten Testkonten verwenden. |
| WA-AUTH-03 | Geschützte Bereiche je Testrolle erfassen | WSTG 4.2 WSTG-ATHZ-02 (unverifiziert) | Testzugang je Rolle | zap:spider+auth | Teilweise automatisch | ja | B | Erfasst erreichbare Seiten pro Rolle. Rollen-Berechtigungsprüfungen (wer darf was) werden NICHT automatisch abgeleitet. |
| WA-ACT-01 | Aktive ZAP-Prüfung mit Profil «webaudit-safe» | WSTG 4.2 WSTG-INPV-01 (unverifiziert) | Freigabe mit Zeitfenster und Limits | zap:ascan | Automatisch | ja | C | Nur vordefinierte, nicht destruktive ZAP-Regeln; keine DoS-, Brute-Force- oder Dateischreib-Tests. Nur innerhalb gültiger Freigabe. |
| WA-REPO-01 | Secrets im Repository (gitleaks) | ASVS 5.0.0 13.3.1<br>CWE 4.20 CWE-798<br>OWASP-TOP10 2025 A04:2025 (unverifiziert) | GitHub-Repository, Lesetoken (optional) | repo:gitleaks | Automatisch | ja | D | Musterbasiert; Fehlalarme möglich. Geprüft wird der feste Commit inkl. Historie bis zur Klontiefe. |
| WA-REPO-02 | Bekannte Schwachstellen in Abhängigkeiten (osv-scanner) | OWASP-TOP10 2025 A03:2025<br>CWE 4.20 CWE-1395 | GitHub-Repository | repo:osv | Automatisch | ja | D | Benötigt Lockfiles; Erreichbarkeit der verwundbaren Funktion wird nicht geprüft. CVE-/GHSA-IDs stammen aus der OSV-Datenbank. |
| WA-REPO-03 | Statische Codeanalyse (semgrep) | OWASP-TOP10 2025 A05:2025 (unverifiziert) | GitHub-Repository | repo:semgrep | Automatisch | ja | D | Regelsatz-Lizenz beachten (siehe docs/catalog.md). Ergebnisse sind Verdachtsfälle, bis sie manuell verifiziert sind. |
| WA-MAN-01 | Zugriffskontrolle und Rollenmodell | OWASP-TOP10 2025 A01:2025<br>WSTG 4.2 WSTG-ATHZ-02 | Rollenmatrix, Testkonten | manual | Manuell | nein | – | Nicht automatisiert. Erfordert manuelle Tests. |
| WA-MAN-02 | Business-Logik | OWASP-TOP10 2025 A06:2025 | Fachliche Spezifikation | manual | Manuell | nein | – | Nicht automatisiert. |
| WA-MAN-03 | Authentifizierungsverfahren (Passwortregeln, MFA, Sperrlogik) | OWASP-TOP10 2025 A07:2025<br>WSTG 4.2 WSTG-ATHN-03<br>WSTG 4.2 WSTG-ATHN-07 | Testkonten | manual | Manuell | nein | – | Nicht automatisiert; Brute-Force-Tests sind ausgeschlossen. |
| WA-MAN-04 | Cross-Site Request Forgery | ASVS 5.0.0 3.5.1<br>WSTG 4.2 WSTG-SESS-05 | Testkonten, zustandsändernde Funktionen | manual | Manuell | nein | – | Erfordert das Absenden von Formularen; im passiven Modus ausgeschlossen. |
| WA-MAN-05 | Protokollierung und Alarmierung | OWASP-TOP10 2025 A09:2025 | Zugang zu Logs/SIEM | manual | Manuell | nein | – | Von aussen nicht prüfbar. |
| WA-MAN-06 | Datenschutzrechtliche Konformität | – | Verzeichnis der Bearbeitungstätigkeiten | manual | Manuell | nein | – | Ausserhalb des Umfangs dieser Plattform. |
