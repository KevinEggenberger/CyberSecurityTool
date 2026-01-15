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

async function runScan(domain) {
  console.log(`🔍 ${domain}`);

  const sslResult = await checkSSL(domain);
  console.log(`   🔐 SSL/TLS: ${sslResult.status}`);
  console.log(`   Empfehlung: ${sslResult.recommendation}\n`);

  const spfResult = await checkSPF(domain);
  console.log(`   SPF: ${spfResult.status}`);
  console.log(`   Empfehlung: ${spfResult.recommendation}\n`);

  const dmarcResult = await checkDMARC(domain);
  console.log(`   DMARC: ${dmarcResult.status}`);
  console.log(`   Empfehlung: ${dmarcResult.recommendation}\n`);

  const apiResult = await scanAPI(domain);
  console.log(`   🔐 API Security Scan: ${apiResult.status}`);
  console.log(`   Empfehlung: ${apiResult.recommendation}\n`);

  const dnsResult = await scanDNS(domain);
  console.log(`   🌐 DNS Security Scan: ${dnsResult.status}`);
  console.log(`   Empfehlung: ${dnsResult.recommendation}\n`);

  const xssResult = await scanXSS(domain);
  console.log(`   🧪 XSS Scanner: ${xssResult.status}`);
  console.log(`   Empfehlung: ${xssResult.recommendation}\n`);

  const webVulns = await scanWebVulns(domain);
  console.log(`   🧨 Web Vulnerability Scan: ${webVulns.status}`);
  console.log(`   Empfehlung: ${webVulns.recommendation}\n`);

  const wpResult = await scanWordPress(domain);
  console.log(`   🧱 WordPress Scan: ${wpResult.status}`);
  console.log(`   Empfehlung: ${wpResult.recommendation}\n`);

  const portResults = await scanPorts(domain);
  console.log(`   🔌 Open Ports:`);
  for (const [port, result] of Object.entries(portResults)) {
    console.log(`   - Port ${port} (${result.service}): ${result.status}`);
  }
  console.log("");

  const subdomains = await checkSubdomains(domain);
  console.log(`   🌐 Gefundene Subdomains:`);
  if (subdomains.length > 0) {
    subdomains.forEach((sub) => console.log(`   - ${sub}`));
  } else {
    console.log(`   Keine öffentlichen Subdomains gefunden.`);
  }
  console.log("");

  const cookieResult = await checkCookies(domain);
  console.log(`   🍪 Cookie Scanner: ${cookieResult.status}`);
  console.log(`   Empfehlung: ${cookieResult.recommendation}\n`);

  const oauthResult = await checkOAuth(domain);
  console.log(`   🔐 OAuth-Check: ${oauthResult.status}`);
  console.log(`   Empfehlung: ${oauthResult.recommendation}\n`);

  const cspResult = await validateCSP(domain);
  console.log(`   🛡️ CSP-Validator: ${cspResult.status}`);
  console.log(`   Empfehlung: ${cspResult.recommendation}\n`);

  const headerResults = await checkSecurityHeaders(domain);
  if (headerResults.error) {
    console.log(`   Header-Scan: FEHLER`);
    console.log(`   Grund: ${headerResults.message}\n`);
  } else {
    console.log(`   🔐 HTTP Security Header Check:`);
    for (const [header, result] of Object.entries(headerResults)) {
      console.log(`   - ${header}: ${result.status}`);
      console.log(`     Empfehlung: ${result.recommendation}`);
    }
    console.log("");
  }

  const scoreResult = calculateScore({
    ssl: sslResult,
    spf: spfResult,
    dmarc: dmarcResult,
    api: apiResult,
    dns: dnsResult,
    xss: xssResult,
    webvuln: webVulns,
    wordpress: wpResult,
    ports: portResults,
    subdomains: subdomains,
    headers: headerResults.error ? null : headerResults,
    cookie: cookieResult,
    csp: cspResult,
    oauth: oauthResult,
  });

  console.log(
    `   📊 Sicherheitsbewertung: ${scoreResult.score}/${scoreResult.maxScore} Punkte\n`
  );
  console.log(
    `   📊 Sicherheitsbewertung (Prozent): ${scoreResult.percentage}%\n`
  );

  console.log("📦 Cluster-Scores:");
  for (const [clusterName, cluster] of Object.entries(scoreResult.clusters)) {
    console.log(
      `   - ${clusterName}: ${cluster.score}/${cluster.maxScore} Punkte (${cluster.percentage}%)`
    );
  }
}

(async () => {
  for (const domain of domains) {
    await runScan(domain);
  }
})();
