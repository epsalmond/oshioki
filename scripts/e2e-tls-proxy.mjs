#!/usr/bin/env node
// e2e-tls-proxy: serve the E2E origin (https://sudo.test) over TLS and
// forward every request to the plain-HTTP server. The Playwright spec runs
// the same proxy in-process; this copy serves the hook's `pin` step after
// Playwright exits. Reads OSHIOKI_TLS_KEY, OSHIOKI_TLS_CERT,
// OSHIOKI_HTTPS_PORT (default 443), and OSHIOKI_SERVER_HTTP.
import { readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";

const target = new URL(process.env.OSHIOKI_SERVER_HTTP ?? "http://server:8443");
const proxy = https.createServer({
  key: readFileSync(process.env.OSHIOKI_TLS_KEY),
  cert: readFileSync(process.env.OSHIOKI_TLS_CERT),
}, (request, response) => {
  const upstream = http.request({
    hostname: target.hostname,
    // A URL with no explicit port leaves target.port empty; the upstream is
    // plain HTTP, so that means 80.
    port: target.port || 80,
    path: request.url,
    method: request.method,
    headers: { ...request.headers, host: target.host },
  }, (upstreamResponse) => {
    response.writeHead(upstreamResponse.statusCode, upstreamResponse.headers);
    upstreamResponse.pipe(response);
  });
  upstream.on("error", () => {
    response.writeHead(502, { "content-type": "text/plain" });
    response.end("upstream unavailable");
  });
  request.pipe(upstream);
});
proxy.listen(Number(process.env.OSHIOKI_HTTPS_PORT ?? "443"), "127.0.0.1", () => {
  console.log("tls proxy listening");
});
