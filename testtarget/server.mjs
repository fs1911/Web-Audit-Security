// Isolierte Testanwendung mit absichtlich fehlerhafter Konfiguration.
// NUR LOKAL: bindet ausschliesslich an 127.0.0.1. Niemals öffentlich deployen.
//
// TESTTARGET_FIXED=1 → «behobene» Variante für Wiederholungsscans.
import http from "node:http";
import https from "node:https";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

const HOST = "127.0.0.1";
const HTTP_PORT = Number(process.env.TESTTARGET_HTTP_PORT ?? 8081);
const HTTPS_PORT = Number(process.env.TESTTARGET_HTTPS_PORT ?? 8443);
const DIR = path.resolve(process.env.TESTTARGET_DIR ?? "var/testtarget");
const FIXED = process.env.TESTTARGET_FIXED === "1";
const SESSION_TOKEN = process.env.TESTTARGET_SESSION_TOKEN ?? "tt-session-SuperGeheim-4711";
fs.mkdirSync(DIR, { recursive: true });

if (HOST !== "127.0.0.1") throw new Error("Testziel darf nur lokal laufen");

const keyPath = path.join(DIR, "key.pem");
const certPath = path.join(DIR, "cert.pem");
if (!fs.existsSync(keyPath)) {
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", keyPath, "-out", certPath, "-days", "30", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"], { stdio: "ignore" });
}
const hitsLog = path.join(DIR, "hits.log");
let revoked = false;

function token() {
  try {
    return fs.readFileSync(path.join(DIR, "verification-token.txt"), "utf8").trim();
  } catch {
    return "";
  }
}

function page(title, body) {
  return `<!doctype html><html lang="de"><head><meta charset="utf-8"><title>${title}</title></head><body><h1>${title}</h1>${body}
<nav><a href="/">Start</a> <a href="/about">Über uns</a> <a href="/products/1">Produkt 1</a> <a href="/products/2">Produkt 2</a> <a href="/contact">Kontakt</a> <a href="/logout">Abmelden</a> <a href="/danger/delete?id=1">Eintrag löschen</a> <a href="https://example.org/extern">Extern</a></nav></body></html>`;
}

function baseHeaders(res, secure) {
  if (FIXED) {
    res.setHeader("Server", "webserver");
    if (secure) res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    res.setHeader("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    res.setHeader("Cache-Control", "no-store");
  } else {
    res.setHeader("Server", "Apache/2.4.1 (Unix)");
    res.setHeader("X-Powered-By", "PHP/5.6.40");
  }
}

function handler(secure) {
  return (req, res) => {
    const url = new URL(req.url, `${secure ? "https" : "http"}://${req.headers.host}`);
    fs.appendFileSync(hitsLog, `${new Date().toISOString()} ${secure ? "https" : "http"} ${req.method} ${url.pathname}${url.search}\n`);
    if (!secure && FIXED && url.pathname !== "/.well-known/webaudit-verification.txt") {
      res.writeHead(301, { Location: `https://127.0.0.1:${HTTPS_PORT}${url.pathname}${url.search}` });
      return res.end();
    }
    baseHeaders(res, secure);
    if (!FIXED && req.headers.origin) {
      res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
      res.setHeader("Access-Control-Allow-Credentials", "true");
    }
    const send = (status, html, type = "text/html; charset=utf-8") => {
      res.writeHead(status, { "Content-Type": type });
      res.end(html);
    };
    switch (true) {
      case url.pathname === "/.well-known/webaudit-verification.txt":
        return send(200, token() + "\n", "text/plain");
      case url.pathname === "/.well-known/security.txt":
        return FIXED ? send(200, "Contact: mailto:security@example.invalid\nExpires: 2027-12-31T23:00:00.000Z\n", "text/plain") : send(404, "nicht gefunden", "text/plain");
      case url.pathname === "/.git/HEAD":
        return FIXED ? send(404, "nicht gefunden", "text/plain") : send(200, "ref: refs/heads/main\n", "text/plain");
      case url.pathname === "/":
        res.setHeader("Set-Cookie", FIXED ? ["__Host-sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax", "prefs=hell; Path=/; Secure; SameSite=Lax"] : ["sessionid=abc123; Path=/", "prefs=hell; Path=/"]);
        return send(200, page("Testseite WebAudit", FIXED ? "<p>Behobene Variante.</p>" : `<p>Absichtlich fehlerhaft konfiguriert.</p><!-- TODO: admin password im Backend entfernen --><img src="http://127.0.0.1:${HTTP_PORT}/logo.png" alt="Logo"><script src="http://127.0.0.1:${HTTP_PORT}/app.js"></script>`));
      case url.pathname === "/about":
        return send(200, page("Über uns", "<p>Testinhalt.</p>"));
      case /^\/products\/\d+$/.test(url.pathname):
        return send(200, page("Produkt", `<p>Produkt ${url.pathname.split("/")[2]}</p><a href="/products/${Number(url.pathname.split("/")[2]) + 1}">Nächstes</a>`));
      case url.pathname === "/contact":
        if (req.method === "POST") {
          fs.appendFileSync(path.join(DIR, "forbidden.log"), `POST /contact ${new Date().toISOString()}\n`);
          return send(200, page("Danke", ""));
        }
        return send(200, page("Kontakt", `<form method="post" action="/contact"><input name="email"><textarea name="msg"></textarea><button>Senden</button></form>`));
      case url.pathname.startsWith("/danger/"):
        fs.appendFileSync(path.join(DIR, "forbidden.log"), `${req.method} ${url.pathname}${url.search} ${new Date().toISOString()}\n`);
        return send(200, page("Gelöscht", "<p>Dieser Aufruf hätte nie erfolgen dürfen.</p>"));
      case url.pathname === "/logout": {
        const auth = req.headers.authorization ?? "";
        if (FIXED && auth === `Bearer ${SESSION_TOKEN}`) revoked = true;
        return send(200, page("Abgemeldet", ""));
      }
      case url.pathname.startsWith("/admin"): {
        const ok = req.headers.authorization === `Bearer ${SESSION_TOKEN}` && !revoked;
        if (!ok) return send(401, page("Anmeldung erforderlich", "<p>Kein Zugriff.</p>"));
        return send(200, page("Admin-Bereich", `<p>Willkommen im geschützten Bereich mit vielen internen Informationen für Testzwecke. ${"Lorem ipsum ".repeat(20)}</p><a href="/admin/users">Benutzer</a> <a href="/admin/settings">Einstellungen</a>`));
      }
      case url.pathname === "/robots.txt":
        return send(200, "User-agent: *\nDisallow: /danger/\n", "text/plain");
      case url.pathname === "/logo.png" || url.pathname === "/app.js":
        return send(200, "", url.pathname.endsWith(".js") ? "application/javascript" : "image/png");
      default:
        return send(404, page("Nicht gefunden", ""));
    }
  };
}

http.createServer(handler(false)).listen(HTTP_PORT, HOST, () => console.log(`[testtarget] http://${HOST}:${HTTP_PORT} (${FIXED ? "behoben" : "fehlerhaft"})`));
https.createServer({ key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) }, handler(true)).listen(HTTPS_PORT, HOST, () => console.log(`[testtarget] https://${HOST}:${HTTPS_PORT}`));
