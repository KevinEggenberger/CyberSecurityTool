const axios = require("axios");
const puppeteer = require("puppeteer");

async function sendRequest(url) {
  try {
    const res = await axios.get(url, { timeout: 3000 });
    let body = "";

    if (typeof res.data === "string") {
      body = res.data;
    } else if (Buffer.isBuffer(res.data)) {
      body = res.data.toString("utf8");
    } else {
      body = JSON.stringify(res.data);
    }

    return {
      statusCode: res.status,
      headers: res.headers,
      body,
    };
  } catch {
    return null;
  }
}

async function getRenderedHTML(url) {
  try {
    // Prefer an explicit Chrome/Edge executable when available (faster, avoids Chromium download issues)
    const possiblePaths = [
      process.env.PUPPETEER_EXECUTABLE_PATH,
      "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
      "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
      "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
    ].filter(Boolean);

    let exePath = null;
    for (const p of possiblePaths) {
      try {
        if (require("fs").existsSync(p)) {
          exePath = p;
          break;
        }
      } catch (e) {
        // ignore
      }
    }

    const launchOpts = {
      headless: true,
      args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-gpu"],
    };
    if (exePath) launchOpts.executablePath = exePath;

    const browser = await puppeteer.launch(launchOpts);
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: "networkidle2", timeout: 20000 });
    const html = await page.content();
    await browser.close();
    return html;
  } catch (err) {
    console.log("❌ Puppeteer-Fehler:", err.message);
    return null;
  }
}

async function scanWordPress(domain) {
  const baseUrl = `https://${domain}`;
  const findings = [];

  const wpCorePaths = ["/wp-login.php", "/wp-admin/", "/readme.html"];
  let wpHits = 0;
  let coreHits = 0;
  let version = null;

  const checks = [
    {
      path: "/wp-login.php",
      name: "Login-Seite",
      score: 2,
      status: "WARNUNG",
      problem:
        "Die Login-Seite ist öffentlich erreichbar und kann Ziel für Brute-Force-Angriffe sein.",
      fix: 'Absichern mit Captcha, Rate-Limit, IP-Whitelist oder Plugin wie "Limit Login Attempts".',
    },
    {
      path: "/wp-admin/",
      name: "Admin-Bereich",
      score: 1,
      status: "WARNUNG",
      problem:
        "Der Admin-Bereich ist erreichbar – potenzielles Ziel für automatisierte Angriffe.",
      fix: 'Zugang mit 2FA schützen und ggf. Pfad mit Plugin wie "WPS Hide Login" ändern.',
    },
    {
      path: "/wp-content/",
      name: "wp-content sichtbar",
      score: 1,
      status: "WARNUNG",
      problem:
        "Das Verzeichnis wp-content ist öffentlich – Plugins und Themes sind sichtbar.",
      fix: "Zugriff per .htaccess oder Server-Regeln einschränken, Directory Listing deaktivieren.",
    },
    {
      path: "/readme.html",
      name: "Versionsleck",
      score: 1,
      status: "WARNUNG",
      problem:
        "Die readme.html verrät die WordPress-Version – erleichtert gezielte Angriffe.",
      fix: "Datei löschen oder per Server-Konfiguration blockieren.",
    },
    {
      path: "/wp-config.php",
      name: "wp-config sichtbar",
      score: 2,
      status: "KRITISCH",
      problem:
        "Konfigurationsdatei ist öffentlich erreichbar – enthält Datenbank-Zugangsdaten.",
      fix: "Zugriff auf wp-config.php per Server-Regeln blockieren.",
    },
  ];

  for (const check of checks) {
    const url = baseUrl + check.path;
    const res = await sendRequest(url);
    if (res && res.statusCode < 400) {
      wpHits++;
      if (wpCorePaths.includes(check.path)) coreHits++;

      findings.push({
        path: check.path,
        name: check.name,
        status: check.status,
        score: check.score,
        maxScore: 10,
        problem: check.problem,
        fix: check.fix,
      });

      if (check.path === "/readme.html" && res.body.includes("WordPress")) {
        const match = res.body.match(/Version\s([\d.]+)/i);
        if (match) {
          version = match[1];
          findings.push({
            path: "Version",
            name: "Veraltete Version",
            status: "WARNUNG",
            score: 1,
            maxScore: 10,
            problem: `WordPress-Version erkannt: ${version}. Veraltete Versionen sind anfällig für bekannte Exploits.`,
            fix: "WordPress regelmäßig aktualisieren – mindestens auf Version 6.x.",
          });
        }
      }
    }
  }

  // Sicherheits-Header prüfen
  const headerCheck = await sendRequest(baseUrl);
  if (headerCheck && headerCheck.headers) {
    const headers = headerCheck.headers;
    if (!headers["x-frame-options"]) {
      findings.push({
        path: "Header",
        name: "X-Frame-Options fehlt",
        status: "WARNUNG",
        score: 0.5,
        maxScore: 10,
        problem: "X-Frame-Options fehlt – Schutz vor Clickjacking nicht aktiv.",
        fix: 'Header "X-Frame-Options: SAMEORIGIN" setzen.',
      });
    }
    if (!headers["content-security-policy"]) {
      findings.push({
        path: "Header",
        name: "Content-Security-Policy fehlt",
        status: "WARNUNG",
        score: 0.5,
        maxScore: 10,
        problem:
          "Content-Security-Policy fehlt – Schutz vor XSS und Datenlecks nicht aktiv.",
        fix: 'Header "Content-Security-Policy" definieren, z. B. mit Plugin oder Server-Konfiguration.',
      });
    }
  }

  // Gerendertes HTML prüfen
  const renderedHTML = await getRenderedHTML(baseUrl);
  if (renderedHTML) {
    const html = renderedHTML.toLowerCase();
    const wpIndicators = [
      "wp-content",
      "wp-includes",
      "wordpress",
      "generator",
      "wp-json",
      "generatepress",
    ];
    const htmlHits = wpIndicators.filter((i) => html.includes(i));

    if (htmlHits.length >= 1) {
      wpHits += 2;
      coreHits += 1;
      findings.push({
        path: "HTML (gerendert)",
        name: "WordPress erkannt",
        status: "OK",
        score: 1,
        maxScore: 10,
        problem: `WordPress-Spuren im gerenderten HTML gefunden: ${htmlHits.join(
          ", "
        )}`,
        fix: "WordPress scheint aktiv zu sein, aber Pfade sind durch JS oder CDN versteckt.",
      });
    }
  }

  // Bewertung
  if (wpHits < 1) {
    return {
      status: "NICHT ERKANNT",
      recommendation:
        "Keine WordPress-Nutzung festgestellt – Modul wird nicht bewertet.",
      details: [],
      score: 0,
      maxScore: 0,
    };
  }

  const totalScore = findings.reduce((sum, f) => sum + (f.score || 0), 0);
  const maxScore = 10;

  const status =
    totalScore === 0 ? "OK" : totalScore < maxScore ? "WARNUNG" : "KRITISCH";

  return {
    status,
    recommendation:
      status === "OK"
        ? "WordPress erkannt, aber keine öffentlich erreichbaren Schwachstellen gefunden."
        : "Mehrere potenzielle WordPress-Schwachstellen erkannt.",
    details: findings,
    score: totalScore,
    maxScore,
  };
}

module.exports = scanWordPress;
