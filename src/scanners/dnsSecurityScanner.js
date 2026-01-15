const dns = require('dns').promises;

async function scanDNS(domain) {
  const details = [];

  // MX
  try {
    const mx = await dns.resolveMx(domain);
    if (!mx || mx.length === 0) {
      details.push({
        name: 'MX-Eintrag',
        status: 'KRITISCH',
        problem: 'Es wurden keine MX-Einträge gefunden. E‑Mail-Zustellung kann fehlschlagen oder unsachgemäß konfiguriert sein.',
        fix: 'MX-Einträge beim DNS-Provider korrekt setzen und auf gültige Mailserver verweisen.',
      });
    } else {
      details.push({
        name: 'MX-Eintrag',
        status: 'OK',
        problem: `MX-Einträge gefunden: ${mx.map(m=>m.exchange).join(', ')}.`,
        fix: 'Keine Aktion erforderlich, wenn die MX-Einträge beabsichtigt sind.',
      });
    }
  } catch (err) {
    details.push({
      name: 'MX-Eintrag',
      status: 'FEHLER',
      problem: 'MX-Abfrage fehlgeschlagen oder keine Berechtigung, die Daten zu lesen.',
      fix: 'DNS-Provider prüfen; ggf. Zonendateien und TTLs kontrollieren.',
    });
  }

  // SPF (TXT mit v=spf1)
  try {
    const txt = await dns.resolveTxt(domain);
    const joined = txt.map(r => r.join('')).join(' ');
    if (joined.toLowerCase().includes('v=spf1')) {
      details.push({
        name: 'SPF-Eintrag',
        status: 'OK',
        problem: `SPF-Eintrag gefunden: ${joined.match(/v=spf1[^;\n]*/i) || ''}`,
        fix: 'SPF-Eintrag regelmäßig prüfen und nur autorisierte Mailserver aufnehmen.',
      });
    } else {
      details.push({
        name: 'SPF-Eintrag',
        status: 'WARNUNG',
        problem: 'Kein SPF-Eintrag (v=spf1) gefunden. Dies erhöht die Wahrscheinlichkeit von E‑Mail-Spoofing.',
        fix: 'Erstellen Sie einen SPF-TXT-Eintrag, z. B. "v=spf1 include:_spf.example.com -all" und testen Sie ihn vor dem Rollout.',
      });
    }
  } catch (err) {
    details.push({
      name: 'SPF-Eintrag',
      status: 'FEHLER',
      problem: 'Fehler beim Auslesen von TXT-Einträgen.',
      fix: 'DNS-Abfragen überprüfen und ggf. Netzwerk/Resolver anpassen.',
    });
  }

  // DMARC
  try {
    const dmarc = await dns.resolveTxt('_dmarc.' + domain);
    const joined = dmarc.map(r => r.join('')).join(' ');
    if (joined.toLowerCase().includes('v=dmarc1')) {
      details.push({
        name: 'DMARC',
        status: 'OK',
        problem: `DMARC-Eintrag gefunden: ${joined}`,
        fix: 'DMARC-Richtlinien regelmäßig prüfen und RO-Reporting aktivieren.',
      });
    } else {
      details.push({
        name: 'DMARC',
        status: 'WARNUNG',
        problem: 'Kein DMARC-Eintrag (_dmarc) gefunden. Ohne DMARC ist die Domain anfälliger für E‑Mail-Spoofing.',
        fix: 'DMARC-TXT-Eintrag anlegen, z. B. "v=DMARC1; p=quarantine; rua=mailto:reports@example.com" und schrittweise durchsetzen.',
      });
    }
  } catch (err) {
    details.push({
      name: 'DMARC',
      status: 'FEHLER',
      problem: 'Fehler beim Lesen des _dmarc TXT-Eintrags.',
      fix: 'DNS-Provider prüfen und DMARC-Eintrag manuell hinzufügen, falls notwendig.',
    });
  }

  // DNSSEC (DNSKEY prüfen, falls unterstützt)
  try {
    let dnskey = null;
    try {
      dnskey = await dns.resolve(domain, 'DNSKEY');
    } catch (e) {
      // einige Resolver/Umgebungen unterstützen DNSKEY nicht; behandeln als nicht signiert
    }
    if (dnskey && dnskey.length > 0) {
      details.push({
        name: 'DNSSEC',
        status: 'OK',
        problem: 'DNSSEC-Schlüssel gefunden – Zone ist signiert.',
        fix: 'Keine Aktion erforderlich, DNSSEC korrekt einrichten und Schlüssel-Rotation planen.',
      });
    } else {
      details.push({
        name: 'DNSSEC',
        status: 'WARNUNG',
        problem: 'Keine DNSSEC-Signaturen gefunden. DNS-Antworten können theoretisch manipuliert werden (z. B. via DNS-Spoofing).',
        fix: 'DNSSEC beim DNS-Provider aktivieren und DS-Record bei Ihrem Registrar hinterlegen.',
      });
    }
  } catch (err) {
    details.push({
      name: 'DNSSEC',
      status: 'FEHLER',
      problem: 'Fehler beim Prüfen von DNSSEC-Daten.',
      fix: 'Prüfen Sie, ob Ihr Resolver DNSSEC-Abfragen unterstützt oder verwenden Sie einen DNS-Testdienst.',
    });
  }

  // Zusammenfassung
  const status = details.some(d => d.status === 'KRITISCH') ? 'KRITISCH' : details.some(d => d.status === 'WARNUNG') ? 'WARNUNG' : 'OK';
  const recommendation = status === 'OK' ? 'DNS-Konfiguration sieht solide aus.' : 'Siehe Details zu DNS-Einträgen und DNSSEC.';

  return {
    status,
    recommendation,
    details,
  };
}

module.exports = scanDNS;
