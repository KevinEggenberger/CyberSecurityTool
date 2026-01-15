const axios = require('axios');

async function scanXSS(domain, options = {}) {
  const base = `https://${domain}`;
  const payload = "<script>/*x*/</script>";
  const testPaths = ['/?q=', '/search?q=', '/?s='];
  const details = [];

  for (const p of testPaths) {
    try {
      const url = base + p + encodeURIComponent(payload);
      const res = await axios.get(url, { timeout: 5000, validateStatus: null });
      const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
      if (body && body.includes(payload)) {
        details.push({
          name: `Reflektiertes XSS möglich: ${p}`,
          status: 'KRITISCH',
          problem: `Das HTML-Payload ${payload} wurde unescaped in der Antwort wiedergegeben. Dies ermöglicht reflektiertes XSS, das Benutzersitzungen und Daten kompromittieren kann.`,
          fix: 'Eingaben auf Server- und Clientseite korrekt escapen/validieren. Verwenden Sie kontextbezogene Escaping-Funktionen und Content-Security-Policy (ohne unsafe-inline).',
        });
      }
    } catch (err) {
      // ignore
    }
  }

  if (details.length === 0) {
    return {
      status: 'OK',
      recommendation: 'Keine einfache reflektierte XSS-Instanz über Standard-Parameter gefunden. Tiefere Tests mit authentifizierten Flows empfohlen.',
      details: [],
    };
  }

  return {
    status: 'KRITISCH',
    recommendation: 'Sofortige Behebung erforderlich: Input-Validierung, Output-Encoding und CSP einsetzen.',
    details,
  };
}

module.exports = scanXSS;

const https = require("https");
const http = require("http");

function sendRequest(url) {
  return new Promise((resolve) => {
    const client = url.startsWith("https") ? https : http;
    const req = client.get(url, { timeout: 3000 }, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        resolve(data);
      });
    });
    req.on("error", () => resolve(null));
    req.end();
  });
}

async function scanXSS(domain) {
  const payload = encodeURIComponent("<script>alert(1)</script>");
  const target = `https://${domain}/?xss=${payload}`;
  const response = await sendRequest(target);

  if (!response) {
    return {
      status: "FEHLER",
      recommendation: "Ziel nicht erreichbar oder blockiert.",
    };
  }

  if (response.includes("<script>alert(1)</script>")) {
    return {
      status: "WARNUNG",
      recommendation:
        "⚠️ Reflected-XSS erkannt – Eingabe wird ungefiltert zurückgegeben.",
    };
  }

  return {
    status: "OK",
    recommendation: "Keine offensichtliche XSS-Schwachstelle erkannt.",
  };
}

module.exports = scanXSS;
