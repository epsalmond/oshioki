#!/usr/bin/env node
// e2e-tls-proxy: serve the E2E origin (https://sudo.test) over TLS and
// forward every request to the plain-HTTP server. The Playwright spec
// imports `startTlsProxy` from here so there is one proxy, not two; running
// this file starts the same proxy for the hook's `enroll` read-back and
// `pin` steps after Playwright exits. Reads OSHIOKI_TLS_KEY, OSHIOKI_TLS_CERT,
// OSHIOKI_HTTPS_PORT (default 443), and OSHIOKI_SERVER_HTTP.
import { readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import { argv } from "node:process";
import { pathToFileURL } from "node:url";

/// Starts the TLS proxy and resolves once it is listening.
export async function startTlsProxy() {
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
  await new Promise((resolve, reject) => {
    proxy.once("error", reject);
    proxy.listen(Number(process.env.OSHIOKI_HTTPS_PORT ?? "443"), "127.0.0.1", resolve);
  });
  return proxy;
}

if (argv[1] && import.meta.url === pathToFileURL(argv[1]).href) {
  await startTlsProxy();
  console.log("tls proxy listening");
}
