import { createDb, getTokenByValue } from '../db';
import type { Env } from '../types';

export async function handleEnrollmentPage(request: Request, env: Env, tokenValue: string): Promise<Response> {
  const db = createDb(env.DB);
  const token = await getTokenByValue(db, tokenValue);

  let status: 'valid' | 'expired' | 'used' | 'revoked' | 'not_found' = 'not_found';
  let remainingUses = 0;

  if (token) {
    if (token.revoked) {
      status = 'revoked';
    } else if (token.useCount >= token.maxUses) {
      status = 'used';
    } else if (new Date(token.expiresAt) < new Date()) {
      status = 'expired';
    } else {
      status = 'valid';
      remainingUses = token.maxUses - token.useCount;
    }
  }

  const serverUrl = new URL(request.url).origin;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Install Open Attest</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #fafafa; color: #18181b; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; }
    .card { background: white; border: 1px solid #e4e4e7; border-radius: 12px; padding: 40px; max-width: 560px; width: 100%; box-shadow: 0 1px 3px rgba(0,0,0,0.06); }
    .logo { display: flex; align-items: center; gap: 8px; margin-bottom: 24px; }
    .logo svg { width: 24px; height: 24px; }
    .logo span { font-size: 18px; font-weight: 600; }
    h1 { font-size: 24px; font-weight: 700; margin-bottom: 8px; }
    .subtitle { color: #71717a; margin-bottom: 32px; }
    .error-card { background: #fef2f2; border-color: #fecaca; }
    .error-card h1 { color: #dc2626; }
    .step { display: flex; gap: 12px; margin-bottom: 20px; }
    .step-num { width: 28px; height: 28px; border-radius: 50%; background: #18181b; color: white; display: flex; align-items: center; justify-content: center; font-size: 13px; font-weight: 600; flex-shrink: 0; margin-top: 2px; }
    .step-content { flex: 1; }
    .step-title { font-weight: 600; margin-bottom: 4px; }
    .step-desc { color: #71717a; font-size: 14px; line-height: 1.5; }
    .download-btns { display: flex; gap: 8px; margin-top: 12px; flex-wrap: wrap; }
    .btn { display: inline-flex; align-items: center; gap: 6px; padding: 8px 16px; border-radius: 8px; font-size: 14px; font-weight: 500; text-decoration: none; cursor: pointer; border: none; transition: all 0.15s; }
    .btn-primary { background: #18181b; color: white; }
    .btn-primary:hover { background: #27272a; }
    .btn-outline { background: white; color: #18181b; border: 1px solid #e4e4e7; }
    .btn-outline:hover { background: #f4f4f5; }
    .code-block { background: #18181b; color: #e4e4e7; padding: 16px; border-radius: 8px; font-family: 'SF Mono', Consolas, monospace; font-size: 13px; line-height: 1.6; margin-top: 12px; overflow-x: auto; position: relative; white-space: pre-wrap; word-break: break-all; }
    .copy-btn { position: absolute; top: 8px; right: 8px; background: #27272a; border: 1px solid #3f3f46; color: #a1a1aa; padding: 4px 10px; border-radius: 6px; font-size: 12px; cursor: pointer; font-family: inherit; }
    .copy-btn:hover { color: white; background: #3f3f46; }
    .info { background: #f0f9ff; border: 1px solid #bae6fd; border-radius: 8px; padding: 12px 16px; font-size: 13px; color: #0369a1; margin-top: 24px; }
    .remaining { color: #71717a; font-size: 13px; margin-top: 4px; }
    .tab-container { margin-top: 12px; }
    .tabs { display: flex; gap: 0; border-bottom: 1px solid #e4e4e7; margin-bottom: 0; }
    .tab { padding: 8px 16px; font-size: 13px; font-weight: 500; cursor: pointer; border: none; background: none; color: #71717a; border-bottom: 2px solid transparent; transition: all 0.15s; }
    .tab.active { color: #18181b; border-bottom-color: #18181b; }
    .tab-panel { display: none; }
    .tab-panel.active { display: block; }
  </style>
</head>
<body>
  <div class="card${status !== 'valid' ? ' error-card' : ''}">
    <div class="logo">
      <svg viewBox="0 0 32 32" fill="none"><path d="M16 2L4 7v7c0 7.73 5.12 14.97 12 17 6.88-2.03 12-9.27 12-17V7L16 2z" fill="#18181b"/><path d="M14 17l-3-3-1.5 1.5L14 20l8-8-1.5-1.5L14 17z" fill="white"/></svg>
      <span>Open Attest</span>
    </div>

    ${status === 'valid' ? `
    <h1>Install Open Attest</h1>
    <p class="subtitle">Set up endpoint attestation on this device in under 2 minutes.</p>
    <p class="remaining">${remainingUses > 1 ? `This link can be used ${remainingUses} more times.` : 'This is a single-use link.'} Expires ${new Date(token!.expiresAt).toLocaleDateString()}.</p>

    <div style="margin-top:24px">
      <div class="step">
        <div class="step-num">1</div>
        <div class="step-content">
          <div class="step-title">Download the agent</div>
          <div class="step-desc">Download the binary for your platform from GitHub Releases.</div>
          <div class="download-btns">
            <a href="https://github.com/screenata/open-attest/releases/latest" target="_blank" class="btn btn-primary">
              Download from GitHub
            </a>
          </div>
        </div>
      </div>

      <div class="step">
        <div class="step-num">2</div>
        <div class="step-content">
          <div class="step-title">Enroll this device</div>
          <div class="step-desc">Open Terminal (macOS/Linux) or PowerShell (Windows) and paste:</div>
          <div class="tab-container">
            <div class="tabs">
              <button class="tab active" onclick="showTab('macos')">macOS / Linux</button>
              <button class="tab" onclick="showTab('windows')">Windows</button>
            </div>
            <div id="tab-macos" class="tab-panel active">
              <div class="code-block" id="cmd-macos">open-attest enroll --token ${tokenValue} --server ${serverUrl}<button class="copy-btn" onclick="copyCmd('macos')">Copy</button></div>
            </div>
            <div id="tab-windows" class="tab-panel">
              <div class="code-block" id="cmd-windows">open-attest.exe enroll --token ${tokenValue} --server ${serverUrl}<button class="copy-btn" onclick="copyCmd('windows')">Copy</button></div>
            </div>
          </div>
        </div>
      </div>

      <div class="step">
        <div class="step-num">3</div>
        <div class="step-content">
          <div class="step-title">Done</div>
          <div class="step-desc">The agent will run in the background and report device posture automatically. No further action needed.</div>
        </div>
      </div>
    </div>

    <div class="info">
      The agent collects: disk encryption status, firewall status, screen lock settings, OS version, antivirus presence, password policy, admin status, hostname, OS username, and device model/serial. It does not collect files, browsing history, or application data. It does not modify your system.
    </div>
    ` : `
    <h1>${status === 'expired' ? 'Link Expired' : status === 'used' ? 'Link Already Used' : status === 'revoked' ? 'Link Revoked' : 'Link Not Found'}</h1>
    <p class="subtitle">${
      status === 'expired' ? 'This enrollment link has expired. Please ask your admin for a new one.' :
      status === 'used' ? 'This enrollment link has reached its usage limit. Please ask your admin for a new one.' :
      status === 'revoked' ? 'This enrollment link has been revoked. Please ask your admin for a new one.' :
      'This enrollment link is not valid. Please check the URL or ask your admin for a new one.'
    }</p>
    `}
  </div>

  <script>
    function showTab(platform) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      event.target.classList.add('active');
      document.getElementById('tab-' + platform).classList.add('active');
    }
    function copyCmd(platform) {
      const el = document.getElementById('cmd-' + platform);
      const text = el.textContent.replace('Copy', '').trim();
      navigator.clipboard.writeText(text);
      const btn = el.querySelector('.copy-btn');
      btn.textContent = 'Copied!';
      setTimeout(() => btn.textContent = 'Copy', 2000);
    }
  </script>
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}
