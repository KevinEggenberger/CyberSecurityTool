const axios = require('axios');

async function scanWebVulns(domain, options = {}) {
  const base = `https://${domain}`;
  const details = [];

  try {
    // Check for exposed dotfiles or config files
    const sensitivePaths = ['/.env', '/config.php', '/.git/config', '/.htaccess', '/web.config'];
    for (const p of sensitivePaths) {
      try {
        const res = await axios.get(base + p, { timeout: 4000, validateStatus: null });
        if (res.status && res.status < 400 && res.data) {
          details.push({
            name: `Exponierte Datei ${p}`,
            status: 'KRITISCH',
            problem: `Die Datei ${p} ist über HTTP erreichbar. Solche Dateien können sensible Konfigurationen oder Schlüssel enthalten.`,
            fix: 'Zugriff auf Konfigurations- und Systemdateien per Server-Regel blockieren und Inhalte aus öffentlichen Verzeichnissen entfernen.',
          });
        }
      } catch (e) {
        // ignore
      }
    }

    // Directory listing check (simple heuristic)
    try {
      const res = await axios.get(base + '/uploads/', { timeout: 4000, validateStatus: null });
      const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
      if (body && (body.includes('Index of') || body.includes('Directory listing for') || body.includes('<title>Index of')) ) {
        details.push({
          name: 'Directory Listing',
          status: 'WARNUNG',
          problem: 'Directory listing ist aktiv in /uploads/ (oder ähnlichem) und zeigt Dateinamen öffentlich an.',
          fix: 'Directory Listing deaktivieren (z. B. per webserver config) und sensible Dateien entfernen.',
        });
      }
    } catch (e) {
      // ignore
    }

    // Server header leakage
    try {
      const root = await axios.get(base, { timeout: 5000, validateStatus: null });
      const server = root.headers && (root.headers['server'] || root.headers['Server'.toLowerCase()]);
      if (server) {
        details.push({ name: 'Server-Header', status: 'WARNUNG', problem: `Server-Header offenbart: ${server}`, fix: 'Server-Header entfernen oder verallgemeinern (z. B. "Server: web").' });
      }
    } catch (e) {
      // ignore
    }

    if (details.length === 0) {
      return { status: 'OK', recommendation: 'Keine einfachen Web-Vulnerabilities gefunden. Tiefere Scans empfohlen.', details: [] };
    }

    const status = details.some(d => d.status === 'KRITISCH') ? 'KRITISCH' : 'WARNUNG';
    return { status, recommendation: 'Siehe Web-Vulnerabilities und beheben Sie kritische Funde zuerst.', details };
  } catch (err) {
    return { status: 'FEHLER', recommendation: 'Fehler beim Überprüfen der Web-Anwendung.', details: [] };
  }
}

module.exports = scanWebVulns;

const https = require("https");
const http = require("http");

function sendRequest(url) {
  return new Promise((resolve) => {
    const client = url.startsWith("https") ? https : http;
    const req = client.get(url, { timeout: 3000 }, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        resolve({ headers: res.headers, body: data });
      });
    });
    req.on("error", () => resolve(null));
    req.end();
  });
}

async function scanWebVulns(domain) {
  const target = `https://${domain}/?id='`;
  const result = await sendRequest(target);
  const findings = [];

  if (!result) {
    return {
      status: "FEHLER",
      recommendation: "Ziel nicht erreichbar oder blockiert.",
    };
  }

  // SQL-Injection Check
  const sqlIndicators = [
    "sql syntax",
    "mysql_fetch",
    "ORA-",
    "unterminated string",
    "query failed",
  ];
  const bodyLower = result.body.toLowerCase();
  const sqlHit = sqlIndicators.some((ind) => bodyLower.includes(ind));
  if (sqlHit) {
    findings.push(
      "⚠️ Mögliche SQL-Injection erkannt – Eingabe nicht ausreichend gefiltert."
    );
  }

  // CORS Check
  const corsHeader = result.headers["access-control-allow-origin"];
  if (
    corsHeader &&
    corsHeader !== "null" &&
    corsHeader !== "same-origin" &&
    corsHeader !== "https://" + domain
  ) {
    findings.push(
      `⚠️ Riskante CORS-Konfiguration: Zugriff erlaubt für "${corsHeader}".`
    );
  }

  if (findings.length === 0) {
    return {
      status: "OK",
      recommendation: "Keine offensichtlichen Web-Schwachstellen erkannt.",
    };
  }

  return { status: "WARNUNG", recommendation: findings.join(" ") };
}

module.exports = scanWebVulns;
