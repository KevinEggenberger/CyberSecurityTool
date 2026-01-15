const axios = require('axios');

async function scanOAuth(domain, options = {}) {
  const base = `https://${domain}`;
  const wellKnown = '/.well-known/openid-configuration';
  const details = [];

  try {
    const res = await axios.get(base + wellKnown, { timeout: 5000, validateStatus: null });
    if (res.status && res.status < 400) {
      const body = res.data;
      details.push({
        name: 'Discovery gefunden',
        status: 'OK',
        problem: 'Eine OpenID Connect / OAuth-Discovery-Datei wurde gefunden.',
        fix: 'Stellen Sie sicher, dass die veröffentlichten Endpunkte korrekt sind und keine internen URLs enthalten.',
      });

      if (body.token_endpoint_auth_methods_supported && body.token_endpoint_auth_methods_supported.includes('none')) {
        details.push({
          name: 'Token endpoint auth methods',
          status: 'KRITISCH',
          problem: 'Der Token-Endpunkt erlaubt "none" als Authentifizierungsmethode. Dies kann die Ausstellung von Tokens ohne Client-Authentifizierung erlauben.',
          fix: 'Deaktivieren Sie "none" für sensible Clients. Verwenden Sie immer client_secret_basic, private_key_jwt oder PKCE für öffentliche Clients.',
        });
      }

      if (body.issuer && !body.issuer.includes(domain)) {
        details.push({
          name: 'Issuer Abgleich',
          status: 'WARNUNG',
          problem: `Der im Discovery-Dokument angegebene Issuer (${body.issuer}) stimmt nicht mit der geprüften Domain überein.`,
          fix: 'Stellen Sie sicher, dass der Issuer korrekt gesetzt ist und keine falschen internen Hosts veröffentlicht werden.',
        });
      }

      if (!body.token_endpoint) {
        details.push({
          name: 'Token Endpoint',
          status: 'FEHLER',
          problem: 'Kein Token-Endpunkt im Discovery-Dokument gefunden.',
          fix: 'Discovery-Dokument korrekt konfigurieren und Token-Endpunkt publizieren.',
        });
      }
    } else {
      return { status: 'NICHT ERKANNT', recommendation: 'Keine OAuth/OpenID-Discovery-Datei gefunden.', details: [
        {
          name: 'OAuth/OpenID nicht erkannt',
          status: 'NICHT ERKANNT',
          problem: 'Es wurde keine OAuth/OpenID-Discovery-Datei unter /.well-known/openid-configuration gefunden.',
          fix: 'Falls OAuth/OpenID verwendet wird, stelle sicher, dass die Discovery-Datei unter dem korrekten Pfad erreichbar ist.',
        }
      ] };
    }
  } catch (err) {
    return { status: 'FEHLER', recommendation: 'Fehler beim Abrufen der Discovery-Datei.', details: [
      {
        name: 'OAuth-Abfrage fehlgeschlagen',
        status: 'FEHLER',
        problem: `Die Abfrage der OAuth/OpenID-Discovery-Datei ist fehlgeschlagen: ${err.message}`,
        fix: 'Prüfe die Netzwerkverbindung und stelle sicher, dass die Domain erreichbar ist.',
      }
    ] };
  }

  const status = details.some(d => d.status === 'KRITISCH') ? 'KRITISCH' : details.some(d => d.status === 'WARNUNG') ? 'WARNUNG' : 'OK';
  return { status, recommendation: 'Siehe Details zu OAuth/OpenID-Konfiguration.', details };
}

module.exports = scanOAuth;

