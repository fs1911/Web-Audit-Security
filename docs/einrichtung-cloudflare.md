# Einrichtung auf Cloudflare – Schritt für Schritt

Ziel: WebAudit Security läuft auf deinem Cloudflare-Worker **web-audit-security**, mit eigener Supabase-Datenbank, privater Berichtsablage in R2 und dem ZAP-Scanner als Cloudflare Container. Alles geht im Browser, du installierst nichts lokal.

**Zeitbedarf:** etwa 30–45 Minuten.

**Rollen:**
- 👤 = machst du im Browser
- 🤖 = mache ich (Claude), sobald du mir Bescheid gibst

**Grundregel:** Passwörter, Connection-Strings und API-Tokens schreibst du **nie in den Chat**. Sie gehören nur in Supabase, Cloudflare oder in die GitHub-Secrets.

---

## Vorab: Was kostet das?

| Dienst | Notwendig | Kosten (ohne Gewähr, Preisseiten prüfen) |
|---|---|---|
| Cloudflare Workers Paid | ja (Container brauchen den Paid-Plan) | monatliche Grundgebühr |
| Cloudflare Containers | ja (ZAP-Scanner) | nach Nutzung (CPU, Arbeitsspeicher, Disk) während eines Scans; ein Basisscan dauert typisch 1–5 Minuten |
| Cloudflare R2 | ja (Berichte) | Gratiskontingent; Berichte sind klein |
| Cloudflare Hyperdrive | ja | im Workers-Plan enthalten |
| Supabase | ja (Datenbank) | Free-Tarif **nur, wenn du noch ein freies Projekt hast** (siehe Schritt 1) |
| Anthropic API | nein (optional) | pro Nutzung |

---

## Schritt 1 👤 – Supabase-Projekt anlegen

**Achtung (Wahrscheinlich):** In deiner Supabase-Organisation laufen bereits **zwei** aktive Projekte (StoffScan, Baustellenkontrolle). Der Free-Tarif erlaubt nach meinem Kenntnisstand nur zwei aktive Projekte pro Organisation. Wenn Supabase beim Anlegen ein Limit meldet, hast du drei Möglichkeiten:
- ein bestehendes Projekt pausieren,
- eine zweite, eigene Organisation anlegen (eigenes Free-Kontingent),
- den Pro-Tarif nehmen.

Teile die Datenbank **nicht** mit einer anderen App.

1. Öffne <https://supabase.com/dashboard> und melde dich an.
2. Klicke **New project**.
3. Fülle aus:
   - **Organization:** deine Organisation
   - **Project name:** `web-audit-security`
   - **Database Password:** auf **Generate a password** klicken und das Passwort **sofort in deinem Passwortmanager speichern**. Du brauchst es in Schritt 6.
   - **Region:** **Central EU (Zurich)**. Falls nicht angeboten: Frankfurt.
4. Klicke **Create new project** und warte, bis «Project is ready» erscheint (1–2 Minuten).

**Ergebnis:** Ein leeres Projekt `web-audit-security` mit Status «Healthy».

---

## Schritt 2 🤖 – Tabellen anlegen

Schreib mir: **«Supabase-Projekt ist angelegt.»**

Ich lege dann über den Supabase-Connector die Tabellen an (Migrationen `drizzle/0000_init.sql` und `drizzle/0001_enable_rls.sql`) und prüfe das Ergebnis. Dabei wird **Row Level Security** auf allen Tabellen aktiviert. So sind die Daten nicht über Supabases öffentliche Daten-API lesbar.

<details><summary>Ausweichweg, falls der Connector nicht verfügbar ist (👤)</summary>

1. Im Supabase-Projekt links **SQL Editor** öffnen → **New query**.
2. Inhalt von [`drizzle/0000_init.sql`](../drizzle/0000_init.sql) einfügen → **Run**.
3. Neue Abfrage mit dem Inhalt von [`drizzle/0001_enable_rls.sql`](../drizzle/0001_enable_rls.sql) → **Run**.
4. Links **Table Editor**: Es müssen 16 Tabellen erscheinen (users, sites, scans, findings …).
</details>

---

## Schritt 3 👤 – Supabase-Daten-API abschalten (empfohlen)

Die App braucht Supabases REST-/GraphQL-API nicht. Wenn du sie abschaltest, fällt eine Angriffsfläche weg.

1. Im Projekt: **Project Settings** (Zahnrad) → **Data API**.
2. Den Schalter **Enable Data API** ausschalten und speichern.

Falls die Menüpunkte bei dir anders heissen: Dieser Schritt ist optional, RLS aus Schritt 2 schützt bereits.

---

## Schritt 4 👤 – Cloudflare Workers Paid aktivieren

1. Öffne <https://dash.cloudflare.com> und melde dich an.
2. Links **Workers & Pages** → **Plans** (je nach Ansicht auch unter **Account Home → Billing → Subscriptions**).
3. **Workers Paid** wählen → **Purchase/Subscribe** und den Kauf bestätigen.

**Ergebnis:** Unter «Plans» steht «Workers Paid» als aktiv.
**Typischer Fehler:** Ohne hinterlegtes Zahlungsmittel fragt Cloudflare zuerst danach.

---

## Schritt 5 👤 – R2 aktivieren

1. Im Cloudflare-Dashboard links **R2 Object Storage**.
2. Klicke **Purchase R2 Plan** (oder «Enable R2») und bestätige. Es gibt ein Gratiskontingent.
3. Einen Bucket musst du **nicht** anlegen. Das übernimmt das Deployment (`web-audit-security-reports`).

**Ergebnis:** Die R2-Übersicht zeigt «Overview» statt der Aktivierungsseite.

---

## Schritt 6 👤 – Hyperdrive mit Supabase verbinden

Hyperdrive ist die Verbindung zwischen Cloudflare und deiner Supabase-Datenbank.

1. **Connection-String in Supabase holen:**
   1. Im Supabase-Projekt oben auf **Connect** klicken.
   2. Reiter **Connection String** → Typ **URI** → Abschnitt **Session pooler** (Port **5432**). Nicht «Transaction pooler».
   3. Den String kopieren. Er sieht so aus: `postgresql://postgres.<projekt-ref>:[YOUR-PASSWORD]@aws-…pooler.supabase.com:5432/postgres`
   4. `[YOUR-PASSWORD]` durch das Passwort aus Schritt 1 ersetzen. Das machst du direkt im Cloudflare-Feld, nicht im Chat.
2. **Hyperdrive anlegen:**
   1. Cloudflare-Dashboard → **Storage & Databases** → **Hyperdrive** → **Create configuration**.
   2. **Name:** `web-audit-security-db`
   3. **Connection string:** den String aus 1. einfügen (mit eingesetztem Passwort).
   4. **Caching:** ausschalten (Disable caching).
   5. **Create** klicken.
3. **ID kopieren:** In der Liste `web-audit-security-db` öffnen und die **ID** kopieren (32 Zeichen, nur 0–9 und a–f). Du brauchst sie in Schritt 8.

**Wichtig:** Nimm **nicht** die bestehende Konfiguration `baustellenkontrolle-db`. Sie gehört zu einer anderen App.
**Typischer Fehler:** «Could not connect» bedeutet meist ein falsches Passwort oder den Transaction-Pooler (Port 6543) statt des Session-Poolers (5432).

---

## Schritt 7 👤 – Cloudflare-API-Token und Account-ID

Den Token braucht GitHub, um in deinem Namen zu deployen.

1. Cloudflare-Dashboard → oben rechts Profil-Symbol → **My Profile** → **API Tokens** → **Create Token**.
2. Bei der Vorlage **Edit Cloudflare Workers** auf **Use template** klicken.
3. **Account Resources:** *Include* → **dein Konto**. Nicht «All accounts».
4. **Zone Resources:** *All zones from an account* → dein Konto. Oder, falls angeboten, ganz entfernen.
5. **Continue to summary** → **Create Token**.
6. Den Token **einmalig kopieren**. Er wird nur jetzt angezeigt.
7. **Account-ID:** Dashboard → **Workers & Pages** → rechte Spalte **Account ID** → kopieren.

**Typischer Fehler:** Scheitert das Deployment später mit einer Berechtigungsmeldung zu Containers oder R2, ergänzt du im Token die in der Meldung genannte Berechtigung (Token bearbeiten → Permissions → hinzufügen).

---

## Schritt 8 👤 – Drei Secrets in GitHub hinterlegen

1. Öffne <https://github.com/fs1911/Web-Audit-Security>.
2. **Settings** → links **Secrets and variables** → **Actions** → **New repository secret**.
3. Drei Secrets anlegen. Der Name muss exakt so geschrieben sein:

| Name | Wert |
|---|---|
| `CLOUDFLARE_API_TOKEN` | Token aus Schritt 7 |
| `CLOUDFLARE_ACCOUNT_ID` | Account-ID aus Schritt 7 |
| `HYPERDRIVE_ID` | ID aus Schritt 6 |

**Ergebnis:** Unter «Repository secrets» stehen genau diese drei Namen. Die Werte bleiben unsichtbar.

---

## Schritt 9 👤 – Freigabe geben

Schreib mir: **«Freigabe: Deployment von web-audit-security auf Cloudflare.»**

Ohne diese ausdrückliche Freigabe löse ich kein Deployment aus. Der Worker enthält heute nur «Hello world» und wird dabei ersetzt.

---

## Schritt 10 👤 – Secrets initialisieren und deployen

1. Auf GitHub im Repository oben den Reiter **Actions** öffnen.
   - Erscheint «Workflows aren't being run on this repository», klickst du **I understand my workflows, go ahead and enable them**.
2. Links **Cloudflare: Secrets initialisieren** → rechts **Run workflow** → **Run workflow**.
   - Der Workflow erzeugt drei zufällige Schlüssel direkt in Cloudflare (`APP_ENCRYPTION_KEY`, `RUNNER_CALLBACK_SECRET`, `RUNNER_SHARED_SECRET`). Niemand sieht sie.
   - Warten, bis der Lauf einen **grünen Haken** hat (ca. 1 Minute).
3. Links **Cloudflare: Deploy** → **Run workflow** → **Run workflow**.
   - Ablauf: Tests → App bauen → Scanner-Image bauen (ZAP, das dauert) → Deployment → Erreichbarkeitsprüfung.
   - Dauer: **15–30 Minuten**, der erste Lauf dauert am längsten.
   - Am Ende steht im Schritt «Erreichbarkeit prüfen» die Adresse, z. B. `App erreichbar: https://web-audit-security.<dein-name>.workers.dev`.

**Wenn ein Lauf rot wird:** Den roten Schritt anklicken, die letzten Zeilen kopieren und mir in den Chat schicken. Dort stehen keine Secrets, GitHub maskiert sie.

**Typische Fehler:**
- «GitHub-Secret … fehlt» → Schritt 8 prüfen.
- «HYPERDRIVE_ID hat nicht das erwartete Format» → Es wurde der Name statt der ID kopiert.
- Authentifizierungsfehler → Token prüfen (Schritt 7).

---

## Schritt 11 👤 – Erstes Konto anlegen

1. Öffne `https://web-audit-security.<dein-name>.workers.dev/register` (die Adresse aus Schritt 10).
2. Name, Organisation, E-Mail und ein Passwort mit **mindestens 12 Zeichen** eingeben → **Konto erstellen**.

Das allererste Konto darf sich registrieren. **Danach ist die Registrierung automatisch geschlossen**, Fremde können sich kein Konto anlegen.

---

## Schritt 12 👤 – Eigene Website hinzufügen und verifizieren

1. Im Dashboard **Website hinzufügen**.
2. Ausfüllen:
   - Name, URL (z. B. `https://staging.deine-domain.ch/`), Umgebung (**Staging** empfohlen), verantwortliche Person.
   - Optional: ausgeschlossene Pfade (z. B. `/admin`, `/checkout`).
   - **Grundlage der Prüfberechtigung** beschreiben und das Häkchen setzen.
3. **Website anlegen**. Die Detailseite zeigt pro Host einen **Token**.
4. Host verifizieren, mit **einer** der beiden Methoden:
   - **Datei:** Auf deiner Website eine Datei unter `/.well-known/webaudit-verification.txt` ablegen, Inhalt = der angezeigte Token. Dann **Datei prüfen**.
   - **DNS** (falls deine Domain bei Cloudflare liegt): Cloudflare-Dashboard → deine Domain → **DNS** → **Records** → **Add record**:
     - Type: `TXT`
     - Name: `_webaudit-verification.<host>` (z. B. `_webaudit-verification.staging`)
     - Content: `webaudit-verification=<Token>`
     - **Save**, 1–5 Minuten warten, dann **DNS prüfen**.
5. **Ergebnis:** Beim Host steht «Verifiziert».

---

## Schritt 13 👤 – Ersten Basischeck starten

1. Auf der Website-Seite **Scan starten**.
2. Modus **A – Schonender Basischeck** lassen und die Limits prüfen (Standard: max. 20 Minuten, 1500 Anfragen, 5 pro Sekunde).
3. Bestätigungshäkchen setzen → **Scan starten**.
4. Der Scan wird innerhalb von **bis zu 1 Minute** übernommen (Cron-Takt). Der erste Containerstart kann einige Minuten dauern.
5. Danach siehst du:
   - die Zusammenfassung,
   - die Feststellungen (getrennt nach Sicherheitslücken, Konfigurationshinweisen und Verdachtsfällen),
   - die Prüfabdeckung,
   - **PDF-/JSON-Bericht erzeugen**,
   - zu jeder Feststellung den **Claude-Code-Reparaturprompt**.

**Wenn der Scan «Fehlgeschlagen» meldet:** Die Fehlermeldung steht oben auf der Scan-Seite. Kopier sie mir. Es werden in diesem Fall nie erfundene Ergebnisse angezeigt.

---

## Danach (optional)

- **KI-Erklärungen:** Cloudflare → Worker `web-audit-security` → **Settings** → **Variables and Secrets** → **Add** → Typ *Secret*, Name `ANTHROPIC_API_KEY`. Dann in der App unter **Einstellungen** die externe KI-Verarbeitung aktivieren.
- **Aktive Prüfungen (Modus C):** bleiben aus, bis du sie ausdrücklich willst. Danach nur auf Staging.
- **Updates:** Nach Codeänderungen erneut **Cloudflare: Deploy** ausführen. **Secrets initialisieren** nicht erneut ausführen. Es würde zwar nichts überschreiben, ist aber unnötig.
