(async () => {
  const checkOAuth = require('./src/scanners/oauthCheck');
  const validateCSP = require('./src/scanners/cspValidator');
  const checkCookies = require('./src/scanners/cookieScanner');
  const scanWordPress = require('./src/scanners/wpScanner');
  const scanXSS = require('./src/scanners/xssScanner');
  const scanDNS = require('./src/scanners/dnsSecurityScanner');
  const scanAPI = require('./src/scanners/apiScanner');
  const scanWebVulns = require('./src/scanners/webVulnScanner');
  const checkSubdomains = require('./src/scanners/subdomainScanner');
  const scanPorts = require('./src/scanners/portScanner');
  const checkSPF = require('./src/scanners/spfScanner');
  const checkDMARC = require('./src/scanners/dmarcScanner');
  const checkSecurityHeaders = require('./src/scanners/headerScanner');
  const checkSSL = require('./src/scanners/sslScanner');

  const domain = process.argv[2] || 'example.com';
  console.log('Running test scan for', domain);

  try {
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

    const results = { ssl, spf, dmarc, api, dns, xss, webvuln, ports, subdomains, cookie, oauth, csp };
    console.log(JSON.stringify({ domain, results }, null, 2));
  } catch (err) {
    console.error('Scan failed:', err);
    process.exit(1);
  }
})();
