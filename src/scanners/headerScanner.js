const axios = require('axios');

const headersToCheck = [
  'strict-transport-security',
  'x-content-type-options',
  'x-frame-options',
  'x-xss-protection',
  'referrer-policy',
  'content-security-policy',
  'permissions-policy',
];

const headerWeight = 5;

async function checkSecurityHeaders(domain) {
  const url = `https://${domain}`;
  const results = {};
  let score = 0;
  const maxScore = headersToCheck.length * headerWeight;

  try {
    const response = await axios.get(url, { timeout: 5000 });
    const responseHeaders = response.headers || {};

    for (const header of headersToCheck) {
      const found = !!responseHeaders[header];
      const status = found ? 'OK' : 'FEHLT';
      const recommendation = found
        ? 'Header vorhanden – gute Absicherung.'
        : `Header "${header}" fehlt. Füge ihn hinzu für besseren Schutz.`;

      const headerScore = found ? headerWeight : 0;
      score += headerScore;

      results[header] = {
        status,
        recommendation,
        score: headerScore,
        maxScore: headerWeight,
      };
    }
  } catch (err) {
    return {
      error: true,
      message: `Fehler beim Abrufen von ${url}: ${err.message}`,
    };
  }

  return {
    ...results,
    score,
    maxScore,
  };
}

module.exports = checkSecurityHeaders;
