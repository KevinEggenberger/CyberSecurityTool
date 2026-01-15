const weights = require("./scoreWeights");
const clusters = require("./scoreClusters");

function calculateScore(results) {
  let totalScore = 0;
  let totalMax = 0;
  const clusterScores = {};

  const scoreMap = {
    OK: 1,
    WARNUNG: 0.5,
    WEAK: 0.5,
    ABGELAUFEN: 0,
    FEHLT: 0,
    FEHLER: null,
    "NICHT PRÜFBAR": null,
    "NICHT ERKANNT": 0,
  };

  // Initialisiere Cluster-Scores
  for (const clusterName of Object.keys(clusters)) {
    clusterScores[clusterName] = { score: 0, maxScore: 0 };
  }

  // Bewertungsfunktion pro Modul
  function addScore(module, status, weight, clusterName) {
    if (status in scoreMap) {
      const factor = scoreMap[status];
      if (factor !== null) {
        const points = Math.round(factor * weight);
        console.log(`Modul: ${module}, Status: ${status}, Punkte: ${points}`);
        totalScore += points;
        totalMax += weight;
        clusterScores[clusterName].score += points;
        clusterScores[clusterName].maxScore += weight;
      }
    }
  }

  // Einzelmodule
  for (const clusterName in clusters) {
    for (const module of clusters[clusterName]) {
      if (module === "headers" && results.headers) {
        const headerWeight = weights.headers / 7;
        for (const [header, result] of Object.entries(results.headers)) {
          addScore(header, result.status, headerWeight, clusterName);
        }
      } else if (results[module]) {
        // Sonderlogik für WordPress
        if (module === "wordpress" && Array.isArray(results[module].tests)) {
          const subScores = results[module].tests.map((t) => {
            const match = t.status.match(/\((\d+)%\)/);
            return match ? parseInt(match[1]) : 0;
          });
          const avgScore =
            subScores.length > 0
              ? Math.round(
                  (subScores.reduce((a, b) => a + b, 0) /
                    subScores.length /
                    100) *
                    (weights[module] || 10)
                )
              : 0;

          console.log(`Modul: wordpress, Durchschnitt: ${avgScore} Punkte`);
          totalScore += avgScore;
          totalMax += weights[module] || 10;
          clusterScores[clusterName].score += avgScore;
          clusterScores[clusterName].maxScore += weights[module] || 10;
        } else {
          addScore(
            module,
            results[module].status,
            weights[module] || 10,
            clusterName
          );
        }
      }
    }
  }

  // Speziallogik: Ports
  if (results.ports) {
    const weight = weights.ports || 10;
    const clusterName = "network";
    const riskPorts = [21, 22, 25, 3306];
    const allowedPorts = [80, 443, 53];
    const unnecessaryPorts = [110, 143, 8080];

    const openPorts = Object.entries(results.ports)
      .filter(([_, info]) => info.status === "OFFEN")
      .map(([port, _]) => parseInt(port));

    let points = 0;
    if (openPorts.length === 0) {
      points = weight;
      console.log(`Modul: ports, Status: ALLE GESCHLOSSEN, Punkte: ${points}`);
    } else if (openPorts.some((p) => riskPorts.includes(p))) {
      points = 0;
      console.log(`Modul: ports, Status: RISKANT, Punkte: ${points}`);
    } else if (openPorts.every((p) => allowedPorts.includes(p))) {
      points = weight;
      console.log(`Modul: ports, Status: NUR ERLAUBT, Punkte: ${points}`);
    } else if (openPorts.some((p) => unnecessaryPorts.includes(p))) {
      points = Math.round(weight * 0.5);
      console.log(`Modul: ports, Status: UNNÖTIG OFFEN, Punkte: ${points}`);
    } else {
      points = Math.round(weight * 0.5);
      console.log(`Modul: ports, Status: UNKLAR, Punkte: ${points}`);
    }

    totalScore += points;
    totalMax += weight;
    clusterScores[clusterName].score += points;
    clusterScores[clusterName].maxScore += weight;
  }

  // Speziallogik: Subdomains
  if (results.subdomains && Array.isArray(results.subdomains)) {
    const weight = weights.subdomains || 10;
    const clusterName = "network";
    const riskSubdomains = [
      "admin",
      "login",
      "dashboard",
      "ftp",
      "backup",
      "old",
      "zugang",
      "intern",
      "portal",
      "webmail",
      "api",
    ];
    const sensitiveSubdomains = [
      "dev",
      "test",
      "staging",
      "beta",
      "static",
      "cdn",
      "m",
      "secure",
    ];

    let points = 0;
    if (results.subdomains.length === 0) {
      points = weight;
      console.log(`Modul: subdomains, Status: KEINE, Punkte: ${points}`);
    } else if (
      results.subdomains.some((sub) =>
        riskSubdomains.some((risk) => sub.includes(risk))
      )
    ) {
      points = 0;
      console.log(`Modul: subdomains, Status: RISKANT, Punkte: ${points}`);
    } else if (
      results.subdomains.some((sub) =>
        sensitiveSubdomains.some((sens) => sub.includes(sens))
      )
    ) {
      points = Math.round(weight * 0.5);
      console.log(`Modul: subdomains, Status: SENSIBEL, Punkte: ${points}`);
    } else {
      points = weight;
      console.log(`Modul: subdomains, Status: NEUTRAL, Punkte: ${points}`);
    }

    totalScore += points;
    totalMax += weight;
    clusterScores[clusterName].score += points;
    clusterScores[clusterName].maxScore += weight;
  }

  console.log("➡️ Gesamtscore:", totalScore);
  console.log("➡️ Maximalwert:", totalMax);

  // Prozentwerte berechnen
  const percentage =
    totalMax > 0 ? Math.round((totalScore / totalMax) * 100) : 0;
  const clustersWithPercent = Object.fromEntries(
    Object.entries(clusterScores).map(([name, data]) => {
      const percent =
        data.maxScore > 0 ? Math.round((data.score / data.maxScore) * 100) : 0;
      return [name, { ...data, percentage: percent }];
    })
  );

  return {
    score: totalScore,
    maxScore: totalMax,
    percentage,
    clusters: clustersWithPercent,
  };
}

module.exports = calculateScore;
