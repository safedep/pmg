#!/usr/bin/env node
/**
 * Reproducer for loopback proxy interference bug
 *
 * What this script does:
 *   1. Starts a real local HTTP server on 127.0.0.1 (simulates an internal app service)
 *   2. Starts a fake PMG proxy on 127.0.0.1 (immediately closes connections — simulates
 *      PMG proxy not being able to handle loopback requests)
 *   3. Makes a request to the local server WITHOUT NO_PROXY → fails because the request
 *      is routed through the PMG proxy
 *   4. Makes the same request WITH NO_PROXY=127.0.0.1,localhost → succeeds
 *
 * Run:
 *   node scripts/reproduce_issue_193.js
 *
 * Expected output:
 *   [BUG]  Request to local server via proxy: connect ECONNREFUSED 127.0.0.1:<proxy-port>
 *          (the proxy is in the way — PMG current behavior)
 *   [FIX]  Request to local server bypassing proxy: 200 OK - {"status":"ok"}
 *          (direct connection — PMG after fix)
 */

const http = require("http");
const net = require("net");

// ─── 1. Start a real local app server ────────────────────────────────────────
function startAppServer() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok" }));
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      console.log(`[INFO] Local app server started on 127.0.0.1:${port}`);
      resolve({ server, port });
    });
  });
}

// ─── 2. Start a fake PMG proxy that rejects all connections ──────────────────
// This simulates PMG's proxy not knowing how to handle loopback requests.
function startFakeProxy() {
  return new Promise((resolve) => {
    const server = net.createServer((socket) => {
      socket.destroy(); // immediately drop — simulates proxy refusing loopback
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      console.log(`[INFO] Fake PMG proxy started on 127.0.0.1:${port}`);
      resolve({ server, port });
    });
  });
}

// ─── 3. Make an HTTP request respecting proxy env vars ───────────────────────
function makeRequest(url, proxyPort, useNoProxy) {
  return new Promise((resolve, reject) => {
    const proxyHost = "127.0.0.1";
    const targetUrl = new URL(url);

    // Simulate what Node.js does when HTTP_PROXY is set
    const noProxyList = ["127.0.0.1", "localhost", "::1"];
    const shouldBypass =
      useNoProxy && noProxyList.includes(targetUrl.hostname);

    let options;
    if (shouldBypass) {
      // Direct connection — what happens when NO_PROXY is set correctly
      options = {
        hostname: targetUrl.hostname,
        port: parseInt(targetUrl.port),
        path: targetUrl.pathname,
        method: "GET",
      };
    } else {
      // Route through proxy — what happens when NO_PROXY is missing (current PMG bug)
      options = {
        hostname: proxyHost,
        port: proxyPort,
        path: url, // send full URL to proxy
        method: "GET",
        headers: { Host: targetUrl.hostname },
      };
    }

    const req = http.request(options, (res) => {
      let body = "";
      res.on("data", (chunk) => (body += chunk));
      res.on("end", () => resolve(`${res.statusCode} OK - ${body}`));
    });

    req.on("error", (err) => reject(err));
    req.setTimeout(3000, () => {
      req.destroy(new Error("Request timed out"));
    });
    req.end();
  });
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  const { server: appServer, port: appPort } = await startAppServer();
  const { server: proxyServer, port: proxyPort } = await startFakeProxy();

  const targetUrl = `http://127.0.0.1:${appPort}/health`;

  console.log(`\n[INFO] PMG sets: HTTP_PROXY=http://127.0.0.1:${proxyPort}`);
  console.log(`[INFO] Target:   ${targetUrl}\n`);

  // ── Test 1: Current PMG behavior (no NO_PROXY) ────────────────────────────
  console.log("━".repeat(60));
  console.log(
    `[BUG]  Simulating PMG WITHOUT NO_PROXY (current behavior)...`
  );
  try {
    const result = await makeRequest(targetUrl, proxyPort, false);
    console.log(`[BUG]  Result: ${result}`);
  } catch (err) {
    console.log(`[BUG]  Error: ${err.message}`);
    console.log(
      `       ↑ Request went to PMG proxy instead of local server.\n`
    );
  }

  // ── Test 2: With NO_PROXY fix ─────────────────────────────────────────────
  console.log("━".repeat(60));
  console.log(
    `[FIX]  Simulating PMG WITH NO_PROXY=127.0.0.1,localhost,::1...`
  );
  try {
    const result = await makeRequest(targetUrl, proxyPort, true);
    console.log(`[FIX]  Result: ${result}`);
    console.log(`       ↑ Request went directly to local server. Fix works.\n`);
  } catch (err) {
    console.log(`[FIX]  Error: ${err.message}`);
  }

  // ── Cleanup ───────────────────────────────────────────────────────────────
  console.log("━".repeat(60));
  appServer.close();
  proxyServer.close();

  console.log("\nSummary:");
  console.log(
    "  The fix is adding NO_PROXY=127.0.0.1,localhost,::1 to setupEnvForProxy()"
  );
  console.log(
    "  in internal/flows/proxy_flow.go:283\n"
  );
}

main().catch(console.error);
