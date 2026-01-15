const axios = require('axios');

async function scanAPI(domain, options = {}) {
  const base = `https://${domain}`;
  const endpoints = [
    '/.well-known/openapi.json',
    '/openapi.json',
    '/swagger.json',
    '/api',
    '/api/',
    '/api/v1',
    '/api/v2',
  ];

  const details = [];

  for (const path of endpoints) {
    try {
      const url = base + path;
      const res = await axios.get(url, { timeout: 5000, validateStatus: null });
      if (res.status && res.status < 400 && res.headers['content-type'] && res.headers['content-type'].includes('json')) {
        const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
        // openapi exposed
        if (body.includes('openapi') || body.includes('swagger') || body.includes('paths')) {
          details.push({
            name: `Offenes API: ${path}`,
            status: 'KRITISCH',
            problem: `Offen zugängliche API-Spezifikation unter ${path} gefunden. Eine öffentlich verfügbare OpenAPI/Swagger-Datei kann Angreifern Endpunkte, Parameter und mögliche Angriffspunkte offenlegen.`,
            fix: 'API-Spezifikationen nicht ungeschützt im Root ablegen. Zugang über Authentifizierung schützen oder die Spezifikation in private Repositories/geschützte Endpunkte verschieben. Falls öffentlich benötigt, entfernen Sie sensitive Pfade/parametern aus der Spezifikation.',
          });
        } else {
          details.push({
            name: `JSON-Endpunkt erreichbar: ${path}`,
            status: 'WARNUNG',
            problem: `JSON-Endpunkt unter ${path} antwortet mit HTTP ${res.status}. Möglicherweise sind API-Endpunkte ohne Authentifizierung erreichbar.`,
            fix: 'Zugriffssteuerung (API-Keys, OAuth2) erzwingen und unnötige Endpunkte entfernen. Implementieren Sie Rate-Limiting und Logging.',
          });
        }

        // CORS prüfen
        const cors = res.headers['access-control-allow-origin'];
        if (cors === '*') {
          details.push({
            name: `CORS: ${path}`,
            status: 'WARNUNG',
            problem: 'Access-Control-Allow-Origin ist auf "*" gesetzt. Das erlaubt beliebigen Seiten, Ihre API per Browser zu erreichen und kann sensitive Antworten exponieren.',
            fix: 'Machen Sie CORS restriktiv: erlauben Sie nur vertrauenswürdige Origins oder entfernen Sie unnötige CORS-Header für sensible Endpunkte.',
          });
        }
      }
    } catch (err) {
      // ignore single endpoint errors
    }
  }

  // Baseline: keine Details gefunden
  if (details.length === 0) {
    return {
      status: 'OK',
      recommendation: 'Keine öffentlich auffindbaren API-Spezifikationen oder offenen JSON-Endpunkte entdeckt.',
      details: [],
    };
  }

  return {
    status: details.some(d => d.status === 'KRITISCH') ? 'KRITISCH' : 'WARNUNG',
    recommendation: 'Überprüfen und schützen Sie die entdeckten API-Endpunkte gemäß den Details.',
    details,
  };
}

module.exports = scanAPI;

const https = require("https");
const http = require("http");

const endpoints = [
  "/api",
  "/api/v1",
  "/api/users",
  "/api/login",
  "/graphql",
  "/rest",
  "/data",
  "/backend",
  "/admin/api",
];

function sendRequest(url) {
  return new Promise((resolve) => {
    const client = url.startsWith("https") ? https : http;
    const req = client.get(url, { timeout: 3000 }, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        resolve({ statusCode: res.statusCode, body: data });
      });
    });
    req.on("error", () => resolve(null));
    req.end();
  });
}

async function scanAPI(domain) {
  const baseUrl = `https://${domain}`;
  const findings = [];

  for (const endpoint of endpoints) {
    const url = baseUrl + endpoint;
    const res = await sendRequest(url);
    if (res && res.statusCode < 400 && res.body.length > 0) {
      findings.push(`⚠️ Offen: ${endpoint} – Antwortcode ${res.statusCode}`);
    }
  }

  if (findings.length === 0) {
    return {
      status: "OK",
      recommendation: "Keine öffentlich erreichbaren API-Endpunkte gefunden.",
    };
  }

  return {
    status: "WARNUNG",
    recommendation: findings.join(" "),
  };
}

module.exports = scanAPI;
