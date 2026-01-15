// utils/scoreClusters.js
module.exports = {
  network: ["ssl", "dns", "ports", "subdomains"],
  web: ["xss", "webvuln", "wordpress", "headers", "csp"],
  auth: ["api", "oauth"],
  mail: ["spf", "dmarc"],
  privacy: ["cookie"],
};
