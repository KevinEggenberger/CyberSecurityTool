const dns = require("dns").promises;

async function checkSPF(domain) {
  try {
    const records = await dns.resolveTxt(domain);
    const spfRecord = records.flat().find((r) => r.startsWith("v=spf1"));
    
    if (!spfRecord)
      return {
        status: "FEHLT",
        recommendation: "Füge einen SPF-Eintrag hinzu.",
        details: [
          {
            name: "SPF-Eintrag fehlt",
            status: "KRITISCH",
            problem: "Es existiert kein SPF-Eintrag (v=spf1) für diese Domain. Das macht die Domain anfällig für E-Mail-Spoofing – Angreifer können E-Mails im Namen deiner Domain versenden.",
            fix: "Füge in den DNS-Einstellungen einen SPF-Eintrag hinzu, z. B.: v=spf1 ip4:YOUR_IP -all oder v=spf1 include:_spf.google.com -all. Nutze den SPF-Record-Generator deines Mail-Providers.",
          }
        ]
      };
    
    if (spfRecord.includes("~all"))
      return {
        status: "WARNUNG",
        recommendation: "Ändere ~all zu -all für mehr Sicherheit.",
        details: [
          {
            name: "Schwacher SPF-Endqualifier",
            status: "WARNUNG",
            problem: "Der SPF-Eintrag endet mit ~all (softfail) statt -all (hardfail). Das bedeutet, dass Mails von nicht autorisierten Servern noch akzeptiert werden könnten.",
            fix: "Ändere den SPF-Eintrag von '~all' zu '-all' am Ende. Beispiel: v=spf1 include:_spf.google.com -all. Dies lehnt E-Mails von nicht autorisierten Servern ab.",
          }
        ]
      };
    
    return {
      status: "OK",
      recommendation: "SPF-Konfiguration sieht gut aus.",
      details: [
        {
          name: "SPF-Eintrag vorhanden",
          status: "OK",
          problem: "Ein korrekter SPF-Eintrag mit hardening qualifier '-all' ist konfiguriert.",
          fix: "Keine Aktion erforderlich. Prüfe regelmäßig, dass der SPF-Eintrag aktuell ist, besonders wenn neue Mail-Services hinzukommen.",
        }
      ]
    };
  } catch (err) {
    return {
      status: "FEHLER",
      recommendation: "Domain konnte nicht geprüft werden.",
      details: [
        {
          name: "SPF-Abfrage fehlgeschlagen",
          status: "FEHLER",
          problem: "Die DNS-Abfrage für SPF-Einträge ist fehlgeschlagen. Das kann durch Netzwerkprobleme oder ungültige Domainnamen verursacht werden.",
          fix: "1. Prüfe, dass der Domainname korrekt ist. 2. Stelle sicher, dass die Internetverbindung stabil ist. 3. Versuche es später erneut.",
        }
      ]
    };
  }
}

module.exports = checkSPF;
