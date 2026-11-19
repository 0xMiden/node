// Count CloudFront responses for this job without mixing in other CI traffic.
const http = require("node:http");
const https = require("node:https");

const target = new URL(process.env.CDN_URL);
if (target.protocol !== "https:" || !target.hostname.endsWith(".cloudfront.net")) {
  throw Error("Expected the configured CloudFront hostname");
}
const stats = { attempts: 0, confirmed: 0, unconfirmedResponses: 0, transportErrors: 0,
  originAttempts: 0, bytes: 0, methods: {}, statuses: {} };
const agent = new https.Agent({ keepAlive: true, maxSockets: 160 });
http.createServer((req, res) => {
  if (!["GET", "HEAD"].includes(req.method) || !req.url.startsWith("/")) {
    res.writeHead(405).end();
    return;
  }
  const headers = {};
  for (const h of ["range","if-none-match","if-match","if-modified-since","accept","user-agent"]) {
    if (req.headers[h]) headers[h] = req.headers[h];
  }
  stats.attempts++;
  stats.methods[req.method] = (stats.methods[req.method] || 0) + 1;
  const upstream = https.request({ hostname: target.hostname, path: req.url, method: req.method, headers, agent }, (response) => {
    if (response.headers["x-amz-cf-id"]) stats.confirmed++; else stats.unconfirmedResponses++;
    stats.statuses[response.statusCode] = (stats.statuses[response.statusCode] || 0) + 1;
    const out = { ...response.headers };
    delete out.connection;
    res.writeHead(response.statusCode, out);
    response.on("data", (chunk) => { stats.bytes += chunk.length; });
    response.on("error", () => res.destroy());
    response.pipe(res);
  });
  upstream.on("error", () => {
    stats.transportErrors++;
    if (!res.headersSent) res.writeHead(502);
    res.end();
  });
  upstream.end();
}).listen(18458, "127.0.0.1");
http.createServer((req, res) => {
  if (req.url === "/stats") {
    res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(stats) + "\n");
  } else {
    stats.originAttempts++;
    res.writeHead(403).end();
  }
}).listen(18459, "127.0.0.1");
