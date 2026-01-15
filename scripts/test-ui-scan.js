const fs = require('fs');
const path = require('path');
const puppeteer = require('puppeteer');
const axios = require('axios');

(async () => {
  const outDir = path.join(__dirname, '..', 'reports');
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

  // Try to use system Chrome if present (faster than downloading Chromium)
  const chromePaths = [
    'C:/Program Files/Google/Chrome/Application/chrome.exe',
    'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
  ];
  let exePath = null;
  for (const p of chromePaths) {
    if (fs.existsSync(p)) { exePath = p; break; }
  }

  console.log('Using Chrome executable:', exePath || 'bundled puppeteer Chromium');

  const browser = await puppeteer.launch({
    headless: true,
    executablePath: exePath || undefined,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });

  try {
    const page = await browser.newPage();
    page.setDefaultNavigationTimeout(60000);

    const url = 'http://127.0.0.1:3000/';
    console.log('Navigating to', url);
    await page.goto(url, { waitUntil: 'networkidle2' });

    // fill domain and click analyze
    await page.waitForSelector('#domainInput');
    await page.focus('#domainInput');
    await page.evaluate(() => document.getElementById('domainInput').value = '');
    await page.type('#domainInput', 'example.com');
    await page.click('#analyzeBtn');

    console.log('Clicked analyze — waiting for results...');

    // wait until at least one module shows a percent (not '-') or timeout
    await page.waitForFunction(() => {
      const scores = Array.from(document.querySelectorAll('.module-card .score'));
      return scores.some(s => s.textContent && s.textContent.trim().includes('%'));
    }, { timeout: 60000 }).catch(() => null);

    // give a small extra delay for full rendering
    await new Promise((r) => setTimeout(r, 800));

    const screenshotPath = path.join(outDir, 'demo-scan.png');
    await page.screenshot({ path: screenshotPath, fullPage: true });
    console.log('Saved screenshot to', screenshotPath);

    // Also call the /scan endpoint to save JSON (non-WP for speed)
    try {
      const resp = await axios.post('http://127.0.0.1:3000/scan', new URLSearchParams({ domain: 'example.com', wp: 'false' }).toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 120000,
      });
      const jsonPath = path.join(outDir, 'demo-scan.json');
      fs.writeFileSync(jsonPath, JSON.stringify(resp.data, null, 2));
      console.log('Saved JSON to', jsonPath);
    } catch (err) {
      console.warn('Failed to fetch /scan:', err.message);
    }

  } finally {
    await browser.close();
  }

  console.log('Done');
})();
