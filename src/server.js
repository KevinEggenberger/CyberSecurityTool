const express = require("express");
const path = require("path");
const bodyParser = require("body-parser");

const checkOAuth = require("./scanners/oauthCheck");
const validateCSP = require("./scanners/cspValidator");
const checkCookies = require("./scanners/cookieScanner");
const scanWordPress = require("./scanners/wpScanner");
const scanXSS = require("./scanners/xssScanner");
const scanDNS = require("./scanners/dnsSecurityScanner");
const scanAPI = require("./scanners/apiScanner");
const scanWebVulns = require("./scanners/webVulnScanner");
const checkSubdomains = require("./scanners/subdomainScanner");
const scanPorts = require("./scanners/portScanner");
const checkSPF = require("./scanners/spfScanner");
const checkDMARC = require("./scanners/dmarcScanner");
const checkSecurityHeaders = require("./scanners/headerScanner");
const checkSSL = require("./scanners/sslScanner");
const calculateScore = require("./utils/scoreCalculator");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "..")));

const statusToScore = (status) => {
  switch ((status || "").toUpperCase()) {
    case "OK":
      return 100;
    case "WARNUNG":
      return 50;
    case "KRITISCH":
      return 20;
    case "NEUTRAL":
      return 70;
    case "RISKANT":
      return 20;
    case "FEHLT":
      return 0;
    case "NICHT ERKANNT":
      return 0;
    default:
      return 0;
  }
};

const wrapModule = (name, result) => {
  if (!result) return null;

  console.log("📦 Details für Modul:", name);
  console.log(JSON.stringify(result.details, null, 2));

  let tests = [];
  let score = 0;

  if (Array.isArray(result.details) && result.details.length) {
    tests = result.details.map((d) => {
      const subScore = statusToScore(d.status);
      score += subScore;
      return {
        name: d.name || name,
        status: `${d.status || "?"} (${subScore}%)`,
      };
    });

    score = Math.round(score / result.details.length);
  } else {
    score = statusToScore(result.status);
    tests = [
      { name, status: `${result.status || "OK"} (${score}%)` },
      ...(result.recommendation
        ? [{ name: "Empfehlung", status: result.recommendation }]
        : []),
    ];
  }

  return { score, tests };
};

const aggregateSecurityHeaders = (headersObj) => {
  if (!headersObj || typeof headersObj !== "object")
    return { score: 0, tests: [] };

  const tests = Object.entries(headersObj)
    .filter(([key, val]) => typeof val === "object" && val !== null)
    .map(([key, val]) => {
      const pct = statusToScore(val.status);
      return { name: key, status: `${val.status || "?"} (${pct}%)`, pct };
    });

  const total = tests.length;
  const sum = tests.reduce((acc, t) => acc + t.pct, 0);
  const overallPct = total > 0 ? Math.round(sum / total) : 0;

  return { score: overallPct, tests };
};

app.post("/scan", async (req, res) => {
  const domain = req.body.domain?.trim();
  const wpEnabled = req.body.wp === "true";
  if (!domain) return res.send("Keine Domain angegeben.");

  const start = Date.now();

  const ssl = await checkSSL(domain);
  const spf = await checkSPF(domain);
  const dmarc = await checkDMARC(domain);
  const api = await scanAPI(domain);
  const dns = await scanDNS(domain);
  const xss = await scanXSS(domain);
  const webvuln = await scanWebVulns(domain);
  const ports = await scanPorts(domain);
  const subdomains = await checkSubdomains(domain);
  const cookie = await checkCookies(domain);
  const oauth = await checkOAuth(domain);
  const csp = await validateCSP(domain);
  const headers = await checkSecurityHeaders(domain);

  const wordpress = wpEnabled
    ? await scanWordPress(domain)
    : {
        status: "NICHT ERKANNT",
        recommendation:
          "WordPress-Modul deaktiviert – keine Bewertung durchgeführt.",
        details: [],
        score: 0,
        maxScore: 0,
      };

  // 🔍 Debug-Ausgabe für WordPress-Modul
  if (wpEnabled) {
    console.log("📦 WordPress-Scan-Rohdaten:");
    console.log("Status:", wordpress.status);
    console.log("Empfehlung:", wordpress.recommendation);
    console.log("Details:", wordpress.details?.length || 0);
    console.log("Komplettes Objekt:", JSON.stringify(wordpress, null, 2));
  }

  const score = calculateScore({
    ssl,
    spf,
    dmarc,
    api,
    dns,
    xss,
    webvuln,
    wordpress,
    ports,
    subdomains,
    headers: headers?.error ? null : headers,
    cookie,
    csp,
    oauth,
  });

  const end = Date.now();
  const scanTime = end - start;

  const modules = {
    ssl: wrapModule("SSL", ssl),
    spf: wrapModule("SPF", spf),
    dmarc: wrapModule("DMARC", dmarc),
    api: wrapModule("API", api),
    dns: wrapModule("DNS", dns),
    xss: wrapModule("XSS", xss),
    webvuln: wrapModule("Web Vulnerabilities", webvuln),
    wordpress: wrapModule("WordPress", wordpress),
    ports: wrapModule("Ports", ports),
    subdomains: Array.isArray(subdomains)
      ? {
          score: subdomains.length > 0 ? 100 : 0,
          tests: subdomains.map((s) => ({
            name: s,
            status: "gefunden (100%)",
          })),
        }
      : wrapModule("Subdomains", subdomains),
    cookies: wrapModule("Cookies", cookie),
    csp: wrapModule("CSP", csp),
    oauth: wrapModule("OAuth", oauth),
    "security headers": aggregateSecurityHeaders(headers),
  };

  // Prepare raw module outputs so frontend can show detailed problem/fix entries
  const modulesRaw = {
    ssl,
    spf,
    dmarc,
    api,
    dns,
    xss,
    webvuln,
    wordpress,
    ports,
    subdomains,
    cookies: cookie,
    csp,
    oauth,
    headers,
  };

  res.json({ domain, score, modules, modulesRaw, scanTime });
});

// SSE endpoint für Progress-Tracking (GET, da EventSource nur GET unterstützt)
app.get("/scan-progress", async (req, res) => {
  const domain = req.query.domain?.trim();
  const wpEnabled = req.query.wp === "true";
  if (!domain) {
    res.status(400).send("Keine Domain angegeben.");
    return;
  }

  // SSE Headers setzen
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("Access-Control-Allow-Origin", "*");

  const totalModules = wpEnabled ? 14 : 13;
  let progress = 0;

  const sendProgress = (moduleName) => {
    progress++;
    const percentage = Math.round((progress / totalModules) * 100);
    res.write(`data: ${JSON.stringify({ progress: percentage, module: moduleName })}\n\n`);
    console.log(`📊 Scan-Fortschritt: ${percentage}% (${moduleName})`);
  };

  try {
    sendProgress("SSL");
    const ssl = await checkSSL(domain);

    sendProgress("SPF");
    const spf = await checkSPF(domain);

    sendProgress("DMARC");
    const dmarc = await checkDMARC(domain);

    sendProgress("API");
    const api = await scanAPI(domain);

    sendProgress("DNS");
    const dns = await scanDNS(domain);

    sendProgress("XSS");
    const xss = await scanXSS(domain);

    sendProgress("Web Vulnerabilities");
    const webvuln = await scanWebVulns(domain);

    sendProgress("Ports");
    const ports = await scanPorts(domain);

    sendProgress("Subdomains");
    const subdomains = await checkSubdomains(domain);

    sendProgress("Cookies");
    const cookie = await checkCookies(domain);

    sendProgress("OAuth");
    const oauth = await checkOAuth(domain);

    sendProgress("CSP");
    const csp = await validateCSP(domain);

    sendProgress("Security Headers");
    const headers = await checkSecurityHeaders(domain);

    sendProgress("WordPress");
    const wordpress = wpEnabled
      ? await scanWordPress(domain)
      : {
          status: "NICHT ERKANNT",
          recommendation:
            "WordPress-Modul deaktiviert – keine Bewertung durchgeführt.",
          details: [],
          score: 0,
          maxScore: 0,
        };

    // Berechne Score
    const score = calculateScore({
      ssl,
      spf,
      dmarc,
      api,
      dns,
      xss,
      webvuln,
      wordpress,
      ports,
      subdomains,
      headers: headers?.error ? null : headers,
      cookie,
      csp,
      oauth,
    });

    const modules = {
      ssl: wrapModule("SSL", ssl),
      spf: wrapModule("SPF", spf),
      dmarc: wrapModule("DMARC", dmarc),
      api: wrapModule("API", api),
      dns: wrapModule("DNS", dns),
      xss: wrapModule("XSS", xss),
      webvuln: wrapModule("Web Vulnerabilities", webvuln),
      wordpress: wrapModule("WordPress", wordpress),
      ports: wrapModule("Ports", ports),
      subdomains: Array.isArray(subdomains)
        ? {
            score: subdomains.length > 0 ? 100 : 0,
            tests: subdomains.map((s) => ({
              name: s,
              status: "gefunden (100%)",
            })),
          }
        : wrapModule("Subdomains", subdomains),
      cookies: wrapModule("Cookies", cookie),
      csp: wrapModule("CSP", csp),
      oauth: wrapModule("OAuth", oauth),
      "security headers": aggregateSecurityHeaders(headers),
    };

    // Sende finale Ergebnisse
    const modulesRaw = {
      ssl,
      spf,
      dmarc,
      api,
      dns,
      xss,
      webvuln,
      wordpress,
      ports,
      subdomains,
      cookies: cookie,
      csp,
      oauth,
      headers,
    };

    res.write(`data: ${JSON.stringify({ progress: 100, module: "Fertig", result: { domain, score, modules, modulesRaw } })}\n\n`);
    res.end();
  } catch (err) {
    console.error("Fehler bei Scan-Fortschritt:", err);
    res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
    res.end();
  }
});

app.listen(PORT, () => {
  console.log(`🌐 Server läuft auf http://localhost:${PORT}`);
});
