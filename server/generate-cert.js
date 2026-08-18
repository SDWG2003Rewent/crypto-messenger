const selfsigned = require('selfsigned');
const fs = require('fs');
const path = require('path');

const certsDir = path.join(__dirname, 'certs');
if (!fs.existsSync(certsDir)) {
  fs.mkdirSync(certsDir);
}

const attrs = [{ name: 'commonName', value: 'crypto-messenger' }];
const pems = selfsigned.generate(attrs, {
  days: 365,
  keySize: 2048  // Node.js v24+ требует минимум 2048 бит
});

fs.writeFileSync(path.join(certsDir, 'key.pem'), pems.private);
fs.writeFileSync(path.join(certsDir, 'cert.pem'), pems.cert);

console.log('[CERT] ✅ Self-signed certificate generated (2048-bit)!');
console.log('[CERT] Files saved in server/certs/');
console.log('[CERT] Now run: npm start');
