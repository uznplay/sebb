/**
 * Auto setup CA certificate for HTTPS interception
 */

const forge = require('node-forge');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const CERT_DIR = path.join(__dirname, 'certs');
const CA_KEY_FILE = path.join(CERT_DIR, 'ca-key.pem');
const CA_CERT_FILE = path.join(CERT_DIR, 'ca-cert.pem');

console.log('\x1b[36m╔═══════════════════════════════════════════════════════════════╗\x1b[0m');
console.log('\x1b[36m║         SEB Proxy - Certificate Setup Wizard                 ║\x1b[0m');
console.log('\x1b[36m╚═══════════════════════════════════════════════════════════════╝\x1b[0m');
console.log('');

// Create certs directory
if (!fs.existsSync(CERT_DIR)) {
  fs.mkdirSync(CERT_DIR, { recursive: true });
  console.log('\x1b[32m✓\x1b[0m Created certs directory');
}

// Check if CA already exists
if (fs.existsSync(CA_KEY_FILE) && fs.existsSync(CA_CERT_FILE)) {
  console.log('\x1b[33m!\x1b[0m CA certificate already exists');
  console.log('  Location: ' + CA_CERT_FILE);
  console.log('');
  
  const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
  });
  
  readline.question('Do you want to regenerate it? (y/N): ', (answer) => {
    readline.close();
    if (answer.toLowerCase() === 'y') {
      generateAndInstallCA();
    } else {
      console.log('\x1b[32m✓\x1b[0m Using existing CA certificate');
      console.log('');
      printInstructions();
    }
  });
} else {
  generateAndInstallCA();
}

function generateAndInstallCA() {
  console.log('\x1b[36m→\x1b[0m Generating CA certificate...');
  
  // Generate key pair
  const keys = forge.pki.rsa.generateKeyPair(2048);
  
  // Create certificate
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10); // Valid for 10 years
  
  const attrs = [{
    name: 'commonName',
    value: 'SEB Proxy Root CA'
  }, {
    name: 'countryName',
    value: 'VN'
  }, {
    shortName: 'ST',
    value: 'Ha Noi'
  }, {
    name: 'localityName',
    value: 'Ha Noi'
  }, {
    name: 'organizationName',
    value: 'SEB Proxy'
  }, {
    shortName: 'OU',
    value: 'Development'
  }];
  
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  
  cert.setExtensions([{
    name: 'basicConstraints',
    cA: true
  }, {
    name: 'keyUsage',
    keyCertSign: true,
    digitalSignature: true,
    nonRepudiation: true,
    keyEncipherment: true,
    dataEncipherment: true
  }, {
    name: 'subjectKeyIdentifier'
  }]);
  
  // Self-sign certificate
  cert.sign(keys.privateKey, forge.md.sha256.create());
  
  // Save to files
  const pem = {
    privateKey: forge.pki.privateKeyToPem(keys.privateKey),
    certificate: forge.pki.certificateToPem(cert)
  };
  
  fs.writeFileSync(CA_KEY_FILE, pem.privateKey);
  fs.writeFileSync(CA_CERT_FILE, pem.certificate);
  
  console.log('\x1b[32m✓\x1b[0m CA certificate generated');
  console.log('  Private Key: ' + CA_KEY_FILE);
  console.log('  Certificate: ' + CA_CERT_FILE);
  console.log('');
  
  // Auto install on Windows
  if (process.platform === 'win32') {
    installCAWindows();
  } else {
    printManualInstallInstructions();
  }
}

function installCAWindows() {
  console.log('\x1b[36m→\x1b[0m Installing CA certificate to Windows...');
  
  try {
    // Import to Trusted Root Certification Authorities
    execSync(`certutil -addstore -f "ROOT" "${CA_CERT_FILE}"`, { 
      stdio: 'inherit',
      shell: 'powershell.exe'
    });
    
    console.log('\x1b[32m✓✓✓ CA certificate installed successfully!\x1b[0m');
    console.log('');
    printInstructions();
  } catch (err) {
    console.log('\x1b[31m✗\x1b[0m Auto-install failed. Please run as Administrator.');
    console.log('');
    console.log('\x1b[33mManual installation:\x1b[0m');
    console.log('1. Right-click PowerShell/CMD and select "Run as Administrator"');
    console.log('2. Run this command:');
    console.log(`   certutil -addstore -f "ROOT" "${CA_CERT_FILE}"`);
    console.log('');
  }
}

function printManualInstallInstructions() {
  console.log('\x1b[33mManual CA Installation:\x1b[0m');
  console.log('');
  console.log('Mac/Linux:');
  console.log('  Import the certificate: ' + CA_CERT_FILE);
  console.log('  into your system\'s trusted root certificates');
  console.log('');
}

function printInstructions() {
  console.log('\x1b[36m╔═══════════════════════════════════════════════════════════════╗\x1b[0m');
  console.log('\x1b[36m║                    Next Steps                                 ║\x1b[0m');
  console.log('\x1b[36m╚═══════════════════════════════════════════════════════════════╝\x1b[0m');
  console.log('');
  console.log('1. \x1b[32mStart the proxy:\x1b[0m');
  console.log('   npm start');
  console.log('');
  console.log('2. \x1b[32mConfigure SEB:\x1b[0m');
  console.log('   Network > Proxies > Use SEB proxy settings');
  console.log('   - Enable HTTP: Host=127.0.0.1, Port=8080');
  console.log('   - Enable HTTPS: Host=127.0.0.1, Port=8080');
  console.log('');
  console.log('3. \x1b[32mTest:\x1b[0m');
  console.log('   Access https://exam.fpt.edu.vn');
  console.log('   Headers will be injected automatically!');
  console.log('');
  console.log('\x1b[32m✓ Setup complete!\x1b[0m');
  console.log('');
}

