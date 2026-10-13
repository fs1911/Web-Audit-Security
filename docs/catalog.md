# Prüfkatalog

- Datei: `catalog/checks.json` (Prüfpunkte), `catalog/references.json` (Referenzwerke)
- Version: `catalogVersion` (aktuell **2026.10.0**), Schema-Validierung beim Laden (`src/lib/catalog.ts`)
- Übersicht: [coverage-matrix.md](coverage-matrix.md) (generiert mit `npm run catalog:matrix`)

## Referenzwerke (Stand der Übernahme 13.10.2026)

| Referenz | Version | Rolle | Lizenz/Nutzung | Verifikation |
|---|---|---|---|---|
| OWASP ASVS | 5.0.0 (Mai 2025) | Anforderungsbasis | CC BY-SA 4.0 | Kontrollnummern gegen Tag `v5.0.0` geprüft: V3 (3.3.1–3.4.8), V12 (12.1.1, 12.2.1, 12.2.2), V13 (13.3.1, 13.4.1, 13.4.6). Keine Anforderungstexte übernommen. |
| OWASP WSTG | 4.2 | Methodik | CC BY-SA 4.0 | Test-IDs aus den Abschnittsnummern von v4.2 abgeleitet (z. B. 4.2.7 → WSTG-CONF-07). v5.0 ist in Entwicklung. |
| OWASP Top 10 | 2025 | ergänzende Kategorisierung | CC BY-SA 4.0 | A01–A10:2025, kein Prüfkatalog |
| CWE | 4.20 | Klassifikation | CWE Terms of Use | ZAP-Zuordnungen stammen aus ZAP selbst |
| CVSS | 4.0 | optional | FIRST | Nur übernommen (OSV), nie berechnet |
| ISO/IEC 27002 | 2022 | ergänzend | urheberrechtlich geschützt | **alle Zuordnungen unverifiziert**, nur Control-Nummern |

## Werkzeuge und Lizenzen

| Werkzeug | Lizenz | Einsatz | Hinweis |
|---|---|---|---|
| OWASP ZAP 2.17.0 | Apache-2.0 | Modus A–C | Distribution aus `zaproxy/zap-stable` |
| gitleaks | MIT | Modus D, Secrets | |
| osv-scanner 2.7.0 | Apache-2.0 | Modus D, Abhängigkeiten | Abfragen an osv.dev (Paketnamen/Versionen werden übermittelt) |
| semgrep 1.180.0 (Community Edition) | LGPL-2.1 (Engine) | Modus D, SAST | Standard: eigener Regelsatz `rules/semgrep` (Teil dieses Repos). Regeln aus der Semgrep Registry stehen **(Wahrscheinlich)** unter der «Semgrep Rules License», die die Nutzung in einem Angebot für Dritte einschränkt. Vor Verwendung prüfen. |

## Regeln für Zuordnungen

1. Keine erfundenen Kontrollnummern. Jede Zuordnung trägt `verified: true|false`.
2. `verified: false` bedeutet: Die ID existiert, aber die inhaltliche Zuordnung ist nur teilweise oder nicht gegen eine zulässige Quelle geprüft.
3. CVE nur bei belastbarer Komponentenzuordnung (OSV-Treffer auf konkrete Paketversion).
4. Neue Prüfpunkte: Eintrag in `checks.json`, Implementierung im Runner, Coverage-Meldung, Test, Matrix neu generieren, `catalogVersion` erhöhen.
