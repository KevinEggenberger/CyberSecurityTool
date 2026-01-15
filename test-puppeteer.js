const puppeteer = require('puppeteer');
const fs = require('fs');

(async () => {
  try {
    // Try to detect local Chrome/Edge on Windows as fallback
    const possiblePaths = [
      'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
      'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe'
    ];
    let exePath = process.env.PUPPETEER_EXECUTABLE_PATH || null;
    for (const p of possiblePaths) {
      if (!exePath && fs.existsSync(p)) exePath = p;
    }

    const launchOpts = {
      headless: true,
      args: ['--no-sandbox','--disable-setuid-sandbox','--disable-gpu'],
    };
    if (exePath) launchOpts.executablePath = exePath;

    console.log('Launching puppeteer with options:', launchOpts);

    const browser = await puppeteer.launch(launchOpts);
    const page = await browser.newPage();
    await page.goto('https://example.com', { waitUntil: 'networkidle2', timeout: 30000 });
    console.log('OK: Seite geladen');
    await browser.close();
  } catch (err) {
    console.log('❌ Puppeteer-Fehler (full):');
    console.log(err && err.stack ? err.stack : err);
  }
})();
