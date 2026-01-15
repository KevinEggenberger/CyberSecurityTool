const dns = require('dns').promises;
const fs = require('fs');
const path = require('path');

function loadWordlist() {
  const filePath = path.join(__dirname, '../../data/subdomains.txt');
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    return content
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
  } catch (err) {
    console.error('❌ Subdomain-Wordlist konnte nicht geladen werden:', err.message);
    return [];
  }
}

async function checkSubdomains(domain) {
  const wordlist = loadWordlist();
  const found = [];

  const checks = wordlist.map(async (sub) => {
    const full = `${sub}.${domain}`;
    try {
      await dns.resolve(full);
      found.push(full);
    } catch (err) {
      // nicht gefunden oder Fehler -> ignorieren
    }
  });

  await Promise.all(checks);
  return found;
}

module.exports = checkSubdomains;
