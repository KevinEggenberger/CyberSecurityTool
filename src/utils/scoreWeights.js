// utils/scoreWeights.js
module.exports = {
  ssl: 10,
  spf: 5,
  dmarc: 5,
  api: 20,
  dns: 10,
  xss: 20,
  webvuln: 20,
  wordpress: 10,
  ports: 20,
  subdomains: 10,
  headers: 35, // 7 headers × 5 Punkte
  // Erweiterungsmodule (werden später eingebaut)
  cookie: 10,
  csp: 10,
  oauth: 15,
};
