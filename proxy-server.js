const http = require('http');
const https = require('https');
const net = require('net');
const url = require('url');

// Cấu hình
const CONFIG = {
  PORT: 8080,
  HEADERS: {
    'x-safeexambrowser-configkeyhash': '0321cacbe2e73700407a53ffe4018f79145351086b26791e69cf7563c6657899',
    'x-safeexambrowser-requesthash': 'c3faee4ad084dfd87a1a017e0c75544c5e4824ff1f3ca4cdce0667ee82a5091a'
  },
  ENABLE_LOGGING: true
};

// Logging helper
function log(message, data = '') {
  if (CONFIG.ENABLE_LOGGING) {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] ${message}`, data);
  }
}

// Inject headers vào request
function injectHeaders(headers) {
  const injectedHeaders = { ...headers };
  
  for (const [key, value] of Object.entries(CONFIG.HEADERS)) {
    injectedHeaders[key] = value;
    log(`✓ Header injected: ${key}: ${value}`);
  }
  
  return injectedHeaders;
}

// Xử lý HTTP requests
function handleHttpRequest(req, res) {
  const parsedUrl = url.parse(req.url);
  
  log(`HTTP Request: ${req.method} ${req.url}`);
  
  // Inject headers
  const headers = injectHeaders(req.headers);
  
  // Xóa headers không cần thiết
  delete headers['proxy-connection'];
  
  const options = {
    hostname: parsedUrl.hostname,
    port: parsedUrl.port || 80,
    path: parsedUrl.path,
    method: req.method,
    headers: headers
  };
  
  const proxyReq = http.request(options, (proxyRes) => {
    log(`← Response: ${proxyRes.statusCode} from ${parsedUrl.hostname}`);
    
    // Forward response headers và status
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    
    // Pipe response data
    proxyRes.pipe(res);
  });
  
  // Error handling
  proxyReq.on('error', (err) => {
    log(`✗ Error proxying request:`, err.message);
    res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end('Bad Gateway');
  });
  
  // Forward request body
  req.pipe(proxyReq);
}

// Xử lý HTTPS CONNECT tunneling
function handleHttpsConnect(req, clientSocket, head) {
  const { hostname, port } = url.parse(`http://${req.url}`);
  
  log(`HTTPS CONNECT: ${hostname}:${port}`);
  
  // Tạo connection đến target server
  const serverSocket = net.connect(port || 443, hostname, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    
    // Intercept và inject headers cho HTTPS traffic
    // Note: Để inject headers vào HTTPS, cần SSL interception (phức tạp hơn)
    // Giải pháp này chỉ tunnel, không inject headers vào HTTPS
    
    serverSocket.write(head);
    serverSocket.pipe(clientSocket);
    clientSocket.pipe(serverSocket);
    
    log(`✓ HTTPS Tunnel established to ${hostname}:${port}`);
  });
  
  serverSocket.on('error', (err) => {
    log(`✗ Error connecting to ${hostname}:${port}:`, err.message);
    clientSocket.end();
  });
  
  clientSocket.on('error', (err) => {
    log(`✗ Client socket error:`, err.message);
    serverSocket.end();
  });
}

// Tạo proxy server
const proxyServer = http.createServer(handleHttpRequest);

// Handle HTTPS CONNECT
proxyServer.on('connect', handleHttpsConnect);

// Start server
proxyServer.listen(CONFIG.PORT, () => {
  console.log('═══════════════════════════════════════════════════════════');
  console.log('  SEB Header Injection Proxy Server');
  console.log('═══════════════════════════════════════════════════════════');
  console.log(`  ✓ Server running on: http://localhost:${CONFIG.PORT}`);
  console.log(`  ✓ HTTP Proxy: Enabled (with header injection)`);
  console.log(`  ✓ HTTPS Proxy: Enabled (tunnel mode)`);
  console.log('');
  console.log('  Headers to inject:');
  for (const [key, value] of Object.entries(CONFIG.HEADERS)) {
    console.log(`    - ${key}: ${value}`);
  }
  console.log('');
  console.log('  Configure SEB to use this proxy:');
  console.log(`    Host: 127.0.0.1 or localhost`);
  console.log(`    Port: ${CONFIG.PORT}`);
  console.log(`    Protocol: HTTP`);
  console.log('═══════════════════════════════════════════════════════════');
  console.log('');
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n\n✓ Shutting down proxy server...');
  proxyServer.close(() => {
    console.log('✓ Server closed');
    process.exit(0);
  });
});

