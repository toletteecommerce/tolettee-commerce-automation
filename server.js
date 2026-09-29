import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import { URL } from 'node:url';

const port = Number(process.env.PORT || 8787);
const baseUrl = process.env.PUBLIC_URL || process.env.RENDER_EXTERNAL_URL;
const tokenFile = new URL('./tokens.json', import.meta.url);
const scopes = ['shops_r', 'shops_w', 'listings_r', 'listings_w', 'transactions_r'];
const states = new Map();

function send(res, status, body, type = 'text/html; charset=utf-8') { res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store' }); res.end(body); }
function b64url(value) { return value.toString('base64url'); }
function encryptionKey() { return crypto.createHash('sha256').update(process.env.TOKEN_ENCRYPTION_KEY || '').digest(); }
function saveTokens(tokens) { const iv = crypto.randomBytes(12); const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv); const data = Buffer.concat([cipher.update(JSON.stringify(tokens)), cipher.final()]); fs.writeFileSync(tokenFile, JSON.stringify({ iv: b64url(iv), tag: b64url(cipher.getAuthTag()), data: b64url(data) }), { mode: 0o600 }); }

async function exchange(code, verifier) {
  const form = new URLSearchParams({ grant_type: 'authorization_code', client_id: process.env.ETSY_API_KEYSTRING, redirect_uri: baseUrl + '/oauth/callback', code, code_verifier: verifier });
  const response = await fetch('https://api.etsy.com/v3/public/oauth/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form });
  if (!response.ok) throw new Error('Etsy rejected the authorization.');
  return response.json();
}

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname === '/health') return send(res, 200, JSON.stringify({ ok: true }), 'application/json');
  if (url.pathname === '/connect') {
    if (!baseUrl || !process.env.ETSY_API_KEYSTRING || !process.env.TOKEN_ENCRYPTION_KEY) return send(res, 503, '<h1>Missing deployment settings</h1>');
    const state = b64url(crypto.randomBytes(24)); const verifier = b64url(crypto.randomBytes(48));
    states.set(state, { verifier, expires: Date.now() + 600000 });
    const auth = new URL('https://www.etsy.com/oauth/connect');
    auth.searchParams.set('response_type', 'code'); auth.searchParams.set('client_id', process.env.ETSY_API_KEYSTRING); auth.searchParams.set('redirect_uri', baseUrl + '/oauth/callback'); auth.searchParams.set('scope', scopes.join(' ')); auth.searchParams.set('state', state); auth.searchParams.set('code_challenge', b64url(crypto.createHash('sha256').update(verifier).digest())); auth.searchParams.set('code_challenge_method', 'S256');
    res.writeHead(302, { location: auth.toString() }); return res.end();
  }
  if (url.pathname === '/oauth/callback') {
    const state = url.searchParams.get('state'); const saved = states.get(state); states.delete(state);
    if (!saved || saved.expires < Date.now()) return send(res, 400, '<h1>Authorization expired</h1>');
    try { saveTokens({ ...(await exchange(url.searchParams.get('code'), saved.verifier)), connectedAt: new Date().toISOString(), scopes }); return send(res, 200, '<h1>Etsy connected</h1><p>Automation is ready.</p>'); } catch (error) { return send(res, 502, '<h1>Connection failed</h1><p>' + error.message + '</p>'); }
  }
  return send(res, 200, '<h1>Tolettee Commerce Automation</h1><p><a href="/health">Health</a> · <a href="/connect">Connect Etsy</a></p>');
}).listen(port, () => console.log('Connector listening on ' + port));
