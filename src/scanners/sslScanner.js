const tls = require("tls");

function checkSSL(domain) {
  return new Promise((resolve) => {
    const options = {
      host: domain,
      port: 443,
      servername: domain,
      rejectUnauthorized: false,
    };

    const socket = tls.connect(options, () => {
      const cert = socket.getPeerCertificate();
      if (!cert || !cert.valid_to) {
        resolve({
          status: "FEHLER",
          recommendation: "Zertifikat konnte nicht abgerufen werden.",
          details: [
            {
              name: "Zertifikat-Fehler",
              status: "FEHLER",
              problem: "Das SSL-Zertifikat konnte nicht abgerufen werden. Der Server antwortet möglicherweise nicht oder hat ein ungültiges Zertifikat.",
              fix: "Prüfe die Konfiguration auf dem Server, stelle sicher dass Port 443 erreichbar ist und dass ein gültiges SSL-Zertifikat installiert ist.",
            }
          ]
        });
      } else {
        const expiry = new Date(cert.valid_to);
        const now = new Date();
        const daysLeft = Math.round((expiry - now) / (1000 * 60 * 60 * 24));

        const details = [];
        
        if (daysLeft <= 0) {
          details.push({
            name: "Zertifikat abgelaufen",
            status: "KRITISCH",
            problem: `Das SSL-Zertifikat ist abgelaufen (vor ${Math.abs(daysLeft)} Tagen). Besucher können das Vertrauen in die Seite verlieren und Browser zeigen Warnungen.`,
            fix: "Erneuere das SSL-Zertifikat sofort bei deinem Zertifikatanbieter (z. B. Let's Encrypt, Comodo). Die Erneuerung ist normalerweise kostenlos.",
          });
        } else if (daysLeft <= 30) {
          details.push({
            name: "Zertifikat läuft bald ab",
            status: "WARNUNG",
            problem: `Das SSL-Zertifikat läuft in ${daysLeft} Tagen ab. Nach Ablauf wird die Seite unsicher.`,
            fix: "Erneuere das SSL-Zertifikat bald, um Ausfallzeiten zu vermeiden. Viele Zertifikatanbieter ermöglichen Vorabverlängerung.",
          });
        } else {
          details.push({
            name: "Zertifikat gültig",
            status: "OK",
            problem: `Das SSL-Zertifikat ist gültig und läuft in ${daysLeft} Tagen ab.`,
            fix: "Keine Aktion erforderlich. Notiere dir das Ablaufdatum und erneuere rechtzeitig vorher.",
          });
        }

        resolve({
          status: daysLeft > 0 ? "OK" : "ABGELAUFEN",
          recommendation:
            daysLeft > 0
              ? `Zertifikat gültig – läuft in ${daysLeft} Tagen ab.`
              : "Zertifikat ist abgelaufen – dringend erneuern!",
          details: details,
        });
      }
      socket.end();
    });

    socket.on("error", () => {
      resolve({
        status: "FEHLER",
        recommendation: "SSL-Verbindung konnte nicht hergestellt werden.",
        details: [
          {
            name: "Verbindungsfehler",
            status: "FEHLER",
            problem: "Es konnte keine SSL-Verbindung zu diesem Server hergestellt werden. Das kann verschiedene Ursachen haben: ungültige Konfiguration, Firewall, oder Server antwortet nicht.",
            fix: "1. Prüfe, ob Port 443 auf dem Server erreichbar ist. 2. Überprüfe die Netzwerk-Konfiguration und Firewall-Einstellungen. 3. Stelle sicher, dass OpenSSL korrekt installiert und konfiguriert ist.",
          }
        ]
      });
    });
  });
}

module.exports = checkSSL;
