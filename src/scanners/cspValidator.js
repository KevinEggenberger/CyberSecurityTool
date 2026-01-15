const axios = require('axios');

module.exports = async function validateCSP(domain) {
  const details = [];
  try {
    const response = await axios.get(`https://${domain}`, { timeout: 5000, validateStatus: null });
    const headers = response.headers || {};
    const csp = headers['content-security-policy'] || headers['Content-Security-Policy'.toLowerCase()];

    if (!csp) {
      details.push({
        name: 'CSP fehlt',
        status: 'WARNUNG',
        problem: 'Kein Content-Security-Policy Header gefunden. Ohne CSP ist der Schutz gegen XSS und Daten-Injection reduziert.',
        fix: 'Setzen Sie einen CSP-Header mit restriktiven Direktiven, z. B. "default-src \'self\'; script-src \'self\'". Verwenden Sie Nonces oder Hashes statt unsafe-inline.',
      });
    } else {
      details.push({
        name: 'CSP vorhanden',
        status: 'OK',
        problem: `CSP-Header gefunden: ${csp}`,
        fix: 'CSP regelmäßig überprüfen und Nonces/Hashes einsetzen, um Inline-Skripte sicher zu handhaben.',
      });

      const lower = String(csp).toLowerCase();
      if (lower.includes('unsafe-inline')) {
        details.push({
          name: 'CSP: unsafe-inline',
          status: 'WARNUNG',
          problem: 'Die Directive "unsafe-inline" erlaubt inline-Skripte/styles und reduziert die Wirksamkeit der CSP.',
          fix: 'Vermeiden Sie "unsafe-inline". Nutzen Sie Nonces oder Hashes für notwendige Inline-Skripte.',
        });
      }
      if (lower.includes('unsafe-eval')) {
        details.push({
          name: 'CSP: unsafe-eval',
          status: 'KRITISCH',
          problem: 'Die Directive "unsafe-eval" erlaubt die Auswertung dynamischen Codes (eval) und kann XSS-Angriffe erleichtern.',
          fix: 'Entfernen Sie "unsafe-eval" aus der CSP und refaktorieren Sie betroffene Bibliotheken.',
        });
      }
      if (lower.includes('*')) {
        details.push({
          name: 'CSP: Wildcards',
          status: 'WARNUNG',
          problem: 'CSP enthält Wildcards (*) welche Ressourcen-Beschränkungen schwächen können.',
          fix: 'Vermeiden Sie Wildcards und spezifizieren Sie vertrauenswürdige Domains explizit.',
        });
      }
    }
  } catch (error) {
    return { status: 'FEHLER', recommendation: 'CSP konnte nicht geprüft werden. Verbindung fehlgeschlagen oder Timeout.', details: [
      {
        name: 'CSP-Abfrage fehlgeschlagen',
        status: 'FEHLER',
        problem: `Fehler beim Abruf der Seite: ${error.message}`,
        fix: 'Prüfen Sie die Erreichbarkeit der Domain und versuchen Sie es erneut.',
      }
    ] };
  }

  const status = details.some(d => d.status === 'KRITISCH') ? 'KRITISCH' : details.some(d => d.status === 'WARNUNG') ? 'WARNUNG' : 'OK';
  return { status, recommendation: 'Siehe CSP-Details für empfohlene Maßnahmen.', details };
};
