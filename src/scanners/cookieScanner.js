const axios = require('axios');

async function scanCookies(domain, options = {}) {
  const base = `https://${domain}`;
  const details = [];

  try {
    const res = await axios.get(base, { timeout: 7000, validateStatus: null });
    const setCookie = res.headers && (res.headers['set-cookie'] || res.headers['set-cookie'.toLowerCase()]);
    if (!setCookie || setCookie.length === 0) {
      return {
        status: 'OK',
        recommendation: 'Keine Set-Cookie Header gefunden. Falls die Anwendung Cookies erwartet, prüfen Sie Session-Management.',
        details: [],
      };
    }

    for (const raw of setCookie) {
      const cookie = raw.split(';').map(s => s.trim());
      const name = cookie[0].split('=')[0];
      const attrs = cookie.slice(1).map(a => a.toLowerCase());

      if (!attrs.includes('secure')) {
        details.push({
          name: `Cookie Secure: ${name}`,
          status: 'KRITISCH',
          problem: `Cookie ${name} wird ohne Secure-Flag gesetzt. Bei unverschlüsselten Verbindungen kann der Cookie abgegriffen werden.`,
          fix: 'Setzen Sie das Secure-Flag, sodass Cookies nur über HTTPS gesendet werden (Set-Cookie: Secure).',
        });
      }
      if (!attrs.includes('httponly')) {
        details.push({
          name: `Cookie HttpOnly: ${name}`,
          status: 'WARNUNG',
          problem: `Cookie ${name} fehlt das HttpOnly-Attribut. JavaScript im Browser kann darauf zugreifen, was XSS-Ausnutzung erleichtert.`,
          fix: 'Setzen Sie HttpOnly für Cookies, die nicht vom Client-Script benötigt werden.',
        });
      }
      if (!attrs.some(a => a.startsWith('samesite'))) {
        details.push({
          name: `Cookie SameSite: ${name}`,
          status: 'WARNUNG',
          problem: `Cookie ${name} hat kein SameSite-Attribut. Das erhöht das Risiko von CSRF-Angriffen.`,
          fix: 'Verwenden Sie SameSite=Lax oder SameSite=Strict für authentifizierende Cookies.',
        });
      }
    }

    const status = details.some(d => d.status === 'KRITISCH') ? 'KRITISCH' : details.length ? 'WARNUNG' : 'OK';
    const recommendation = status === 'OK' ? 'Cookie-Flags sind in Ordnung.' : 'Siehe Cookie-Details und setzen Sie empfohlenen Flags.';

    return { status, recommendation, details };
  } catch (err) {
    return {
      status: 'FEHLER',
      recommendation: 'Fehler beim Abruf der Seite. Prüfen Sie Konnektivität.',
      details: [],
    };
  }
}

module.exports = scanCookies;

// scanners/cookieScanner.js
module.exports = async function checkCookies(domain) {
  // Simulierte Logik – später durch echte Analyse ersetzen
  const simulatedCookies = ["_ga", "sessionid", "tracking_cookie"];

  const hasTracking = simulatedCookies.some((c) =>
    ["tracking", "ads", "fb", "pixel"].some((t) => c.includes(t))
  );

  if (hasTracking) {
    return {
      status: "WARNUNG",
      recommendation: "Tracking-Cookies erkannt. DSGVO-Konformität prüfen.",
    };
  } else {
    return {
      status: "OK",
      recommendation: "Keine auffälligen Cookies erkannt.",
    };
  }
};
