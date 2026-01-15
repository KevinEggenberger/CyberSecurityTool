// --- Modul-Erklärungen (global verfügbar) ---
const moduleInfos = {
  ssl: {
    title: "SSL (Secure Sockets Layer)",
    text: "SSL verschlüsselt die Verbindung zwischen Browser und Server. Ohne SSL können sensible Daten abgefangen werden.",
  },
  spf: {
    title: "SPF (Sender Policy Framework)",
    text: "SPF schützt vor E-Mail-Spoofing, indem es festlegt, welche Server E-Mails im Namen deiner Domain senden dürfen.",
  },
  dmarc: {
    title: "DMARC (Domain-based Message Authentication)",
    text: "DMARC ergänzt SPF und DKIM und hilft, gefälschte E-Mails zu erkennen und zu blockieren – wichtig gegen Phishing.",
  },
  cookies: {
    title: "Cookies",
    text: "Cookies speichern Nutzerdaten. Tracking-Cookies können Datenschutzprobleme verursachen. DSGVO-konforme Konfiguration ist wichtig.",
  },
  "security headers": {
    title: "Security Headers",
    text: "HTTP-Sicherheits-Header schützen vor Webangriffen wie Clickjacking, XSS oder Datenlecks. Sie sind einfach und effektiv.",
  },
  wordpress: {
    title: "WordPress",
    text: "WordPress ist ein beliebtes CMS, aber oft Ziel von Angriffen. Sicherheitsupdates und Plugins müssen regelmäßig geprüft werden.",
  },
  api: {
    title: "API-Sicherheit",
    text: "Offene oder unsichere API-Endpunkte können Angriffsflächen bieten. Sie sollten geschützt und dokumentiert sein.",
  },
  dns: {
    title: "DNS-Sicherheit",
    text: "DNSSEC und sichere DNS-Konfigurationen verhindern Manipulationen bei der Namensauflösung und schützen vor Spoofing.",
  },
  xss: {
    title: "XSS (Cross-Site Scripting)",
    text: "XSS erlaubt Angreifern, fremden Code in Webseiten einzuschleusen. Schutz erfolgt durch Input-Validierung und sichere Header.",
  },
  webvuln: {
    title: "Web Vulnerabilities",
    text: "Typische Web-Schwachstellen wie SQL-Injection oder Directory Traversal können zu Datenverlust oder Serverzugriff führen.",
  },
  ports: {
    title: "Offene Ports",
    text: "Offene Ports können Angriffsvektoren sein. Nur notwendige Ports sollten erreichbar sein – z. B. 443 für HTTPS.",
  },
  subdomains: {
    title: "Subdomains",
    text: "Subdomains wie admin.domain.ch oder test.domain.ch können sensible Bereiche offenlegen. Sie sollten geprüft und geschützt werden.",
  },
  csp: {
    title: "Content Security Policy (CSP)",
    text: "CSP verhindert das Laden unerwünschter Inhalte und schützt vor XSS-Angriffen. Eine starke CSP ist essenziell.",
  },
  oauth: {
    title: "OAuth",
    text: "OAuth regelt den sicheren Zugriff auf APIs und Benutzerkonten. Eine korrekte Konfiguration verhindert Missbrauch.",
  },
};

// --- Info-Popup anzeigen ---
function showInfoPopup(title, text) {
  // Vorheriges Popup entfernen, falls vorhanden
  const existing = document.querySelector(".info-popup");
  if (existing) existing.remove();

  // Neues Popup erstellen
  const popup = document.createElement("div");
  popup.className = "info-popup";
  popup.innerHTML = `
    <h4>${title}</h4>
    <p>${text}</p>
    <button class="close-info">Schließen</button>
  `;
  document.body.appendChild(popup);

  popup.querySelector(".close-info").addEventListener("click", () => {
    popup.remove();
  });
}

// Helper: map status text to CSS class
function statusToClass(status) {
  if (!status) return 'gray';
  const s = String(status).toUpperCase();
  if (s.includes('OK') || s === 'OK') return 'green';
  if (s.includes('WARN') || s === 'WARNUNG') return 'yellow';
  if (s.includes('KRIT') || s.includes('FEHL') || s === 'KRITISCH' || s === 'FEHLT') return 'red';
  if (s.includes('NICHT') || s.includes('NICHT ERKANNT')) return 'gray';
  return 'gray';
}

// Helper: map status text to small icon (Unicode)
function statusToIcon(status) {
  if (!status) return 'ℹ';
  const s = String(status).toUpperCase();
  if (s.includes('OK') || s === 'OK') return '✓';
  if (s.includes('WARN') || s === 'WARNUNG') return '⚠';
  if (s.includes('KRIT') || s.includes('FEHL') || s === 'KRITISCH' || s === 'FEHLT') return '✖';
  if (s.includes('NICHT') || s.includes('NICHT ERKANNT')) return 'ℹ';
  return 'ℹ';
}

// --- URL Eingabe + Button ---
const analyzeBtn = document.getElementById("analyzeBtn");
const urlField = document.getElementById("domainInput");

let currentEventSource = null;

// Backend URL - change this to your Render.com URL once deployed
const BACKEND_URL = 'https://cybersecuritytool.onrender.com';

analyzeBtn.addEventListener("click", async () => {
  const url = urlField.value.trim();
  if (!url) return alert("Bitte eine URL eingeben!");

  // Close any existing EventSource connection
  if (currentEventSource) {
    currentEventSource.close();
    currentEventSource = null;
  }

  // Show loading bar
  const loadingContainer = document.querySelector(".loading-bar-container");
  const loadingBar = document.getElementById("loadingBar");
  loadingContainer.classList.add("active");
  loadingBar.style.width = "0%";
  loadingBar.classList.remove("animate");
  void loadingBar.offsetWidth; // Trigger reflow

  try {
    // Open EventSource for real-time progress
    currentEventSource = new EventSource(
      `${BACKEND_URL}/scan-progress?domain=${encodeURIComponent(url)}&wp=true`
    );

    let hasResult = false;
    const timeoutId = setTimeout(() => {
      if (currentEventSource && !hasResult) {
        console.warn("SSE Timeout - forcibly closing connection");
        currentEventSource.close();
        currentEventSource = null;
        loadingContainer.classList.remove("active");
        alert("Scan-Timeout: Bitte versuchen Sie es erneut.");
      }
    }, 120000); // 2 minute timeout

    currentEventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);

        if (data.error) {
          console.error("Scan-Fehler:", data.error);
          clearTimeout(timeoutId);
          if (currentEventSource) {
            currentEventSource.close();
            currentEventSource = null;
          }
          alert("Scan fehlgeschlagen: " + data.error);
          loadingContainer.classList.remove("active");
          return;
        }

        // Update loading bar based on real progress
        const progressPercent = data.progress || 0;
        loadingBar.style.animation = "none";
        loadingBar.style.width = progressPercent + "%";
        loadingBar.style.transition = "width 0.3s ease";

        console.log(
          `📊 Fortschritt: ${progressPercent}% (${data.module})`
        );

        // If scan is complete (100%) and result is available
        if (progressPercent === 100 && data.result && !hasResult) {
          hasResult = true;
          clearTimeout(timeoutId);
          if (currentEventSource) {
            currentEventSource.close();
            currentEventSource = null;
          }

          // Display results
          if (data.result.modules) updateModules(data.result.modules);
          if (data.result.score) updateResult(data.result.score);

          // Hide loading bar after short delay
          setTimeout(() => {
            loadingContainer.classList.remove("active");
            loadingBar.style.transition = "none";
            loadingBar.style.width = "0%";
          }, 300);
        }
      } catch (parseErr) {
        console.error("Fehler beim Parsen SSE-Daten:", parseErr, event.data);
      }
    };

    currentEventSource.onerror = (err) => {
      console.error("EventSource-Fehler:", err);
      clearTimeout(timeoutId);
      if (currentEventSource) {
        currentEventSource.close();
        currentEventSource = null;
      }
      if (!hasResult) {
        loadingContainer.classList.remove("active");
        alert("Verbindung zum Server unterbrochen. Bitte versuchen Sie es erneut.");
      }
    };
  } catch (err) {
    console.error("Fehler bei Analyse:", err);
    alert("Analyse fehlgeschlagen: " + err.message);
    loadingContainer.classList.remove("active");
    if (currentEventSource) {
      currentEventSource.close();
      currentEventSource = null;
    }
  }
});

// --- Module aktualisieren ---
function updateModules(modules, modulesRaw) {
  document.querySelectorAll('.module-card').forEach((card) => {
    const key = card.dataset.module; // e.g. 'ssl', 'dmarc', 'security headers'
    const scoreEl = card.querySelector('.score');
    const detailsEl = card.querySelector('.module-details ul');

    const mod = modules && modules[key];
    const raw = modulesRaw && modulesRaw[key];
    // Some module keys differ between aggregated `modules` and `modulesRaw` (e.g. "security headers" vs "headers").
    let rawData = raw;
    if (!rawData && key === 'security headers' && modulesRaw) rawData = modulesRaw.headers || modulesRaw['security headers'];
    if (!rawData && key === 'cookies' && modulesRaw) rawData = modulesRaw.cookies || modulesRaw['cookies'];

    const pct = mod && typeof mod.score === 'number' ? mod.score : (raw && raw.score) || '–';
    scoreEl.textContent = typeof pct === 'number' ? pct + '%' : '–';

    detailsEl.innerHTML = '';

    // Prefer raw.details if available (contains problem/fix), otherwise fall back to mod.tests
    if (rawData && Array.isArray(rawData.details)) {
      rawData.details.forEach((d, idx) => {
        const li = document.createElement('li');
        const row = document.createElement('div');
        row.className = 'item-row';

        const left = document.createElement('div'); left.className = 'item-left';
        const title = document.createElement('div');
        title.className = 'item-title';
        title.textContent = d.name || `Detail ${idx + 1}`;

        const badge = document.createElement('div');
        badge.className = 'status-badge ' + statusToClass(d.status);
        badge.innerHTML = `<span class="badge-icon">${statusToIcon(d.status)}</span>${d.status || '–'}`;

        left.appendChild(title);

        const right = document.createElement('div'); right.className = 'item-right';
        const toggle = document.createElement('button');
        toggle.className = 'toggle-detail';
        toggle.textContent = 'Details';

        const status = document.createElement('div');
        status.className = 'item-status';
        status.style.minWidth = '56px';
        status.appendChild(badge);

        row.appendChild(left);
        row.appendChild(right);
        right.appendChild(status);
        right.appendChild(toggle);

        const body = document.createElement('div');
        body.className = 'detail-body';
        const prob = document.createElement('div');
        prob.innerHTML = `<strong><span class="detail-icon">${statusToIcon(d.status)}</span>Problem:</strong> ${d.problem || '—'}`;
        const fix = document.createElement('div');
        fix.style.marginTop = '6px';
        fix.innerHTML = `<strong><span class="detail-icon">🛠</span>Fix:</strong> ${d.fix || '—'}`;
        body.appendChild(prob);
        body.appendChild(fix);

        li.appendChild(row);
        li.appendChild(body);

        toggle.addEventListener('click', (ev) => {
          ev.stopPropagation();
          li.classList.toggle('open');
        });

        detailsEl.appendChild(li);
      });
    } else if (key === 'security headers' && rawData && typeof rawData === 'object') {
      // rawData is expected to be the headers object (modulesRaw.headers)
      Object.entries(rawData).forEach(([h, val]) => {
        if (h === 'score' || h === 'maxScore') return;
        const li = document.createElement('li');
        const row = document.createElement('div');
        row.className = 'item-row';

        const left = document.createElement('div'); left.className = 'item-left';
        const title = document.createElement('div'); title.className = 'item-title';
        title.textContent = h;

        const badge = document.createElement('div');
        badge.className = 'status-badge ' + statusToClass(val && val.status);
        badge.innerHTML = `<span class="badge-icon">${statusToIcon(val && val.status)}</span>${(val && val.status) || '–'}`;

        const right = document.createElement('div'); right.className = 'item-right';
        const infoBox = document.createElement('div'); infoBox.className = 'item-status'; infoBox.appendChild(badge);
        const toggle = document.createElement('button'); toggle.className = 'toggle-detail'; toggle.textContent = 'Details';

        left.appendChild(title);
        right.appendChild(infoBox);
        right.appendChild(toggle);

        const body = document.createElement('div'); body.className = 'detail-body';
        const rec = document.createElement('div'); rec.innerHTML = `<strong><span class="detail-icon">ℹ</span>Info:</strong> ${val && val.recommendation ? val.recommendation : 'Keine zusätzliche Info.'}`;
        body.appendChild(rec);

        li.appendChild(row);
        li.appendChild(body);

        row.appendChild(left);
        row.appendChild(right);

        toggle.addEventListener('click', (ev) => { ev.stopPropagation(); li.classList.toggle('open'); });
        detailsEl.appendChild(li);
      });
    } else if (key === 'ports' && raw && typeof raw === 'object') {
      // raw is an object mapping port -> {status, service}
      Object.entries(raw).forEach(([p, info]) => {
        const li = document.createElement('li');
        const row = document.createElement('div');
        row.className = 'item-row';
        const title = document.createElement('div');
        title.className = 'item-title';
        title.textContent = `Port ${p}`;
        const status = document.createElement('div');
        status.className = 'item-status';
        status.textContent = info.status || '–';

        const toggle = document.createElement('button');
        toggle.className = 'toggle-detail';
        toggle.textContent = 'Details';

        const badge = document.createElement('div');
        badge.className = 'status-badge ' + statusToClass(info.status);
        badge.innerHTML = `<span class="badge-icon">${statusToIcon(info.status)}</span>${info.status || '–'}`;

        const left = document.createElement('div'); left.className = 'item-left'; left.appendChild(title);
        const right = document.createElement('div'); right.className = 'item-right';
        const infoBox = document.createElement('div'); infoBox.className = 'item-status'; infoBox.appendChild(badge);
        right.appendChild(infoBox);
        right.appendChild(toggle);

        row.appendChild(left);
        row.appendChild(right);

        const body = document.createElement('div');
        body.className = 'detail-body';
        body.innerHTML = `<strong><span class="detail-icon">🔌</span>Service:</strong> ${info.service || '–'}`;

        li.appendChild(row);
        li.appendChild(body);

        toggle.addEventListener('click', (ev) => {
          ev.stopPropagation();
          li.classList.toggle('open');
        });

        detailsEl.appendChild(li);
      });
    } else if (key === 'subdomains' && Array.isArray(raw)) {
      raw.forEach((s) => {
        const li = document.createElement('li');
        const row = document.createElement('div');
        row.className = 'item-row';
        const title = document.createElement('div');
        title.className = 'item-title';
        title.textContent = s;
        const status = document.createElement('div');
        status.className = 'item-status';
        status.textContent = 'gefunden';
        row.appendChild(title);
        row.appendChild(status);
        li.appendChild(row);
        detailsEl.appendChild(li);
      });
    } else if (mod && Array.isArray(mod.tests)) {
      mod.tests.forEach((t, idx) => {
        const li = document.createElement('li');
        const row = document.createElement('div');
        row.className = 'item-row';
        const title = document.createElement('div');
        title.className = 'item-title';
        title.textContent = t.name || `Test ${idx + 1}`;
        const status = document.createElement('div');
        status.className = 'item-status';
        status.textContent = t.status || '–';

        row.appendChild(title);
        row.appendChild(status);

        li.appendChild(row);
        detailsEl.appendChild(li);
      });
    }
  });
}

// --- Gesamtergebnis aktualisieren ---
function updateResult(score) {
  const resultSection = document.querySelector(".result");
  let color = "red",
    label = "Kritisch";
  if (score.percentage >= 80) {
    color = "green";
    label = "Sehr gut";
  } else if (score.percentage >= 50) {
    color = "yellow";
    label = "Verbesserungswürdig";
  }

  console.log(`Gesamtscore: ${score.percentage}% (${label})`);

  animateScoreRing(score.percentage);
}

function animateScoreRing(percentage) {
  const ring = document.querySelector(".progress-ring");
  const text = document.querySelector(".score-text");
  const radius = 45;
  const circumference = 2 * Math.PI * radius;

  ring.style.strokeDasharray = `${circumference}`;
  ring.style.strokeDashoffset = `${circumference}`;

  let current = 0;
  const step = 1;
  const interval = setInterval(() => {
    if (current >= percentage) {
      clearInterval(interval);
    } else {
      current += step;
      const offset = circumference - (current / 100) * circumference;
      ring.style.strokeDashoffset = offset;
      text.textContent = `${current}%`;

      // Farbverlauf je nach Fortschritt
      if (current < 35) {
        ring.style.stroke = "#ff4d4d"; // Rot
      } else if (current < 75) {
        ring.style.stroke = "#ffcc00"; // Gelb
      } else {
        ring.style.stroke = "#4caf50"; // Grün
      }
    }
  }, 20);
}

// --- Modul-Kacheln aufklappbar machen ---
document.querySelectorAll(".module-card").forEach((card) => {
  card.addEventListener("click", () => {
    card.classList.toggle("active");
  });
});

// --- Info-Icons aktivieren ---
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".info-icon").forEach((icon) => {
    icon.addEventListener("click", () => {
      const key = icon.dataset.module;
      const info = moduleInfos[key];
      if (info) showInfoPopup(info.title, info.text);
    });
  });
});
