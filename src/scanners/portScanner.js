const net = require('net');

const commonPorts = {
  21: 'FTP',
  22: 'SSH',
  25: 'SMTP',
  53: 'DNS',
  80: 'HTTP',
  110: 'POP3',
  143: 'IMAP',
  443: 'HTTPS',
  3306: 'MySQL',
  8080: 'HTTP-Alt',
};

function scanPorts(domain) {
  const timeout = 1000;
  const results = {};

  const checks = Object.entries(commonPorts).map(([port, name]) => {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(timeout);

      socket.on('connect', () => {
        results[port] = { status: 'OFFEN', service: name };
        socket.destroy();
        resolve();
      });

      socket.on('timeout', () => {
        results[port] = { status: 'GESCHLOSSEN', service: name };
        socket.destroy();
        resolve();
      });

      socket.on('error', () => {
        results[port] = { status: 'GESCHLOSSEN', service: name };
        resolve();
      });

      socket.connect(Number(port), domain);
    });
  });

  return Promise.all(checks).then(() => results);
}

module.exports = scanPorts;
