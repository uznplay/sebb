/**
 * Railway Entry Point
 * Generate certificate then start proxy
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 8080;

console.log('🚀 SEB Proxy Starting on Railway...');
console.log('Port:', PORT);

// Check if certificate exists
const certPath = path.join(__dirname, 'certs', 'ca-cert.pem');

if (!fs.existsSync(certPath)) {
  console.log('📜 Certificate not found, generating...');
  
  // Generate certificate FIRST
  const setup = spawn('node', ['setup-certificates.js'], {
    stdio: 'inherit'
  });
  
  setup.on('close', (code) => {
    if (code === 0 || fs.existsSync(certPath)) {
      console.log('✅ Certificate ready');
      startProxy();
    } else {
      console.error('❌ Failed to generate certificate');
      process.exit(1);
    }
  });
} else {
  console.log('✅ Certificate already exists');
  startProxy();
}

function startProxy() {
  console.log('🔥 Starting proxy server...');
  
  const proxy = spawn('node', ['proxy-mitm.js'], {
    stdio: 'inherit',
    env: {
      ...process.env,
      PORT: PORT
    }
  });
  
  proxy.on('error', (err) => {
    console.error('❌ Proxy error:', err);
    process.exit(1);
  });
  
  proxy.on('close', (code) => {
    console.log('⚠️ Proxy exited with code:', code);
    process.exit(code || 0);
  });
  
  // Graceful shutdown
  process.on('SIGTERM', () => {
    console.log('📴 Shutting down gracefully...');
    proxy.kill('SIGTERM');
    setTimeout(() => process.exit(0), 5000);
  });
}
