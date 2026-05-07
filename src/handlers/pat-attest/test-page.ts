/**
 * First-party test page for the PAT challenge flow.
 *
 * Served from the same origin as /v1/pat-attestation so that iOS WebKit
 * sees the fetch as a same-origin XHR — the closest analog to how the
 * production SDK probe will fire. If iOS auto-redeems the PAT, the
 * response body comes back as `{ token, expiryMs }`; if it doesn't, we
 * just get the raw `{ challenge, tokenKey, maxAge }` challenge.
 *
 * Loose-coupling: this file exists ONLY for the smoke test. Delete the
 * file + the path branch in handler.ts + the GET /v1/pat-test route in
 * http-api.ts to remove cleanly.
 */

import type { APIGatewayProxyResultV2 } from "aws-lambda";

const HTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>PAT test — argus</title>
  <style>
    body { font: 14px/1.4 -apple-system, system-ui, sans-serif; padding: 1em; max-width: 60em; margin: 0 auto; color: #222; }
    h1 { font-size: 1.4em; }
    pre { background: #f4f4f4; padding: 0.8em; border-radius: 4px; overflow-x: auto; font-size: 12px; }
    .ok { color: #0a7d2c; font-weight: 600; }
    .bad { color: #b03020; font-weight: 600; }
    .meta { color: #666; font-size: 12px; }
    button { padding: 0.6em 1.2em; font-size: 1em; }
  </style>
</head>
<body>
  <h1>PAT smoke test</h1>
  <p class="meta">Same-origin <code>fetch('/v1/pat-attestation')</code> from real HTML+JS context. iOS Safari should auto-redeem if the OS-level handler fires for this request shape.</p>
  <p><button id="go">Run again</button></p>
  <div id="verdict"></div>
  <h3>Response status</h3><pre id="status">—</pre>
  <h3>WWW-Authenticate header</h3><pre id="wwwauth">—</pre>
  <h3>Response body</h3><pre id="body">—</pre>
  <h3>User-Agent</h3><pre id="ua">—</pre>
  <script>
  document.getElementById('ua').textContent = navigator.userAgent;
  async function run() {
    const verdict = document.getElementById('verdict');
    verdict.innerHTML = '<p class="meta">running…</p>';
    try {
      const res = await fetch('/v1/pat-attestation', { cache: 'no-store' });
      const body = await res.json();
      const wwwAuth = res.headers.get('WWW-Authenticate') || '(none)';
      document.getElementById('status').textContent = res.status + ' ' + res.statusText;
      document.getElementById('wwwauth').textContent = wwwAuth;
      document.getElementById('body').textContent = JSON.stringify(body, null, 2);
      if (body && body.token) {
        verdict.innerHTML = '<p class="ok">✓ iOS REDEEMED — we got a probe token. PAT works on this client.</p>';
      } else if (body && body.challenge) {
        verdict.innerHTML = '<p class="bad">✗ No redemption — got the raw challenge back. iOS did not fire OS-level PAT for this fetch.</p>';
      } else {
        verdict.innerHTML = '<p class="bad">? Unexpected response shape.</p>';
      }
    } catch (e) {
      verdict.innerHTML = '<p class="bad">fetch error: ' + (e && e.message ? e.message : String(e)) + '</p>';
    }
  }
  document.getElementById('go').addEventListener('click', run);
  run();
  </script>
</body>
</html>`;

export function testPageResponse(): APIGatewayProxyResultV2 {
  return {
    statusCode: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
    },
    body: HTML,
  };
}
