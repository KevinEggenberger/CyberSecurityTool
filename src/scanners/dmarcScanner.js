const dns = require("dns").promises;

async function checkDMARC(domain) {
  const dmarcDomain = `_dmarc.${domain}`;
  try {
    const records = await dns.resolveTxt(dmarcDomain);

    if (!records || records.length === 0) {
      return {
        status: "FEHLT",
        recommendation:
          "Kein DMARC-Eintrag gefunden. Füge z. B. folgenden Eintrag hinzu: v=DMARC1; p=none",
      };
    }

    const dmarcRecord = records.flat().find((r) => r.startsWith("v=DMARC1"));

    if (!dmarcRecord) {
      return {
        status: "FEHLT",
        recommendation:
          "DMARC-Eintrag fehlt oder ist ungültig. Beispiel: v=DMARC1; p=none",
      };
    }

    if (dmarcRecord.includes("p=none")) {
      return {
        status: "WEAK",
        recommendation:
          "Setze p=quarantine oder p=reject für besseren Schutz vor Spoofing.",
      };
    }

    return {
      status: "OK",
      recommendation: "DMARC-Konfiguration sieht gut aus.",
    };
  } catch (err) {
    return {
      status: "FEHLER",
      recommendation:
        "Technischer Fehler bei der DNS-Abfrage. Prüfe Domain oder Internetverbindung.",
    };
  }
}

module.exports = checkDMARC;
