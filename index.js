/**
 * CAEP / SSF Transmitter - Full API parity (transmitter-only)
 * - All SSF endpoints implemented for a transmitter:
 *   /.well-known/ssf-configuration
 *   /.well-known/jwks.json
 *   POST /ssf/streams         (create)
 *   GET  /ssf/streams/:id     (get)
 *   POST /ssf/streams/:id     (update)
 *   POST /ssf/streams/:id/delete (delete)
 *   POST /ssf/streams/verify  (verify)
 *   GET  /ssf/status
 *   POST /caep/send-risk-level-change (event push)
 *
 * - Signs SETs (RS256) and stream requests (typ: application/secevent+jwt)
 * - Uses Bearer token (API_TOKEN) for all outbound receiver API calls
 *
 * Usage:
 *   npm install express axios jose uuid body-parser
 *   node index.js
 *
 * Replace PRIVATE_KEY_PEM and API_TOKEN for production.
 */

const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const { SignJWT, importPKCS8, exportJWK, jwtVerify, importJWK } = require('jose');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(bodyParser.json());
const PORT = process.env.PORT || 3000;

/* ---------------------------
   CONFIGURATION (override via env)
   --------------------------- */
const API_TOKEN = process.env.API_TOKEN || 'Bearer test-api-token-12345';
const ISS = (process.env.ISS || 'http://localhost:3000').replace(/\/$/, '');
const DEFAULT_AUD = process.env.AUD || 'https://receiver.example.com/';
const DEFAULT_RECEIVER_URL = process.env.DEFAULT_RECEIVER_URL || 'https://webhook.site/<your-webhook-id>';

/* ---------------------------
   Hardcoded test PKCS#8 private key (for testing only)
   Replace with a secure PEM in production (Render env var PRIVATE_KEY_PEM).
   This key is PKCS#8 format and known to import cleanly.
   --------------------------- */
const FALLBACK_PRIVATE_KEY_PEM = '-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsW9cSawbhvJVm
bLdPlrMXngFV/hx0tBACuIeRn1ivJj4BRBT4OOBlS88/TS+UrK26ZkcByQWc4pnl
51BUAhbUR+pLPMDN2LcoxpHf1S6T3ktBBmYkmxGaN8RCdf88LMc6hKg+/Awl9jyM
VzIwj4RMlEMhK3zjt5rKLUttR2TOXVpUNUOQaHCxVWtZd8c87C/FQy2lSkbjPDEh
Ns7nV4WLCmdvnlNPw3SqdYtIdvkREc1XJbZPbf2u9/Z8S5SJiuD0jd8zTIYDl87z
RgCpoUaHwJwjDbweNxqCOxZZoZeP287GkkRIEQZvgMfzS5RjPR/ADcH4N6XQY1UW
8xemBcjXAgMBAAECggEAP0ZyFQlkm9+rK1BzFY1aDywLCoJA+RkXnaAX6P6KRLax
4a4YUq4ytw1XNsKD2r1wA/PDUqT1YgyQeiXqyASCVAlYuqlBkPBkAVywte8h69ga
YXNTcVHaavbZHpsKChHYTCPiTkkivpcA0Ha8brZpV+HAKT+5WDIR6fIp9CLXH6jr
cE1vEMftmaHQ8FgyTjOvopfnoQNmwJaxBi3jCCo06raozftxPVrP799sT/XcYHnO
Z/n+ubf9ZSrHUDNy9ONwxd5Dh6OVwqzaNv7us9nzBTCbw6rh3//BQ/HJGlBd4q5j
fTpgxruzSopwitipVFe4SFZKMxsOzEYj3aVo5qjgxQKBgQDt5zDbZEAvT/vWCw1Y
p5ee/DbGV7WcLh6v4YrsAB6Gh5eUgOJFHsa4Z22CzTj9L8XCRwM9rfdbPRhTM7XD
gHCmd7oDKSiI1V/I8326j02qWlG6httc+0kBLFvojtXVJI5o29FUdI9MsocBP0Ub
DQWYefh06aP5EcbHslJ943olQwKBgQC5eEVK9RE1tQ16UiISMzoa2ycIpzrrInCC
MRcBVBzg2V7mWtpuXEV5gLF+Yz8WP5mXRF/LW09JGhr2hHSQYFJtwobBeietSl3U
XSN9rI3xBYqUFQKmRJ2n0/rdSWT3giOINvixHy5DSxMDmZDoVhKfCcoME+u9emyF
RCO93fUK3QKBgQC0jjEzYQuhnNeqJGs1rMRTImJD+E9aQFqD6+5unMyOF5yAVazk
/q2dSMoBatXkunwhrZmVF1JTSbQLeYRq4zEb9mQTgApGh4KR1dLHY3lzX+cFZNJZ
6FEI9eyvPLCnen4msSZXLbuQXzI9TRKarDBh/7gEq0oKf2ZZK0qWRq3uVwKBgCiJ
dPuxHJXUgKGfmfrIX4bHJ3zosCP8XwLVn+WWcMlkOS235c4BNN4dlq29G2jNddBu
DVHxHx8nKYV/5co4g0uiHLnk7Q8fFer4gG1TbaKkR2mePfoBPUQVPNto0zyVoRaA
jVKJMh9bJUjAI7/kMCW6igKhyACd5WIrRnSVMp2xAoGATPDGisPOOORjkIz8TCEF
D3YhMq84PIj5r5uDSFo6vDA8Z/r5g5sv2SJWyKRkWeIolzsdKMzZii0eQXvzIQN2
jzBfeBWtkDwWrXLyK1X6u8vNrnidk5tzSqWxsozxNvc2bfA/L5AfOuhGevCddv4t
M+9P+DyEd3vGxg7tEiWa2Bg=
-----END PRIVATE KEY-----';

/* Prefer env key if present (allow multi-line env) */
let PRIVATE_KEY_PEM = FALLBACK_PRIVATE_KEY_PEM;
if (process.env.PRIVATE_KEY_PEM && process.env.PRIVATE_KEY_PEM.trim()) {
  PRIVATE_KEY_PEM = process.env.PRIVATE_KEY_PEM.trim();
}

/* ---------------------------
   In-memory store for streams
   --------------------------- */
const streams = {}; // stream_id -> stream object

/* ---------------------------
   JOSE key init
   --------------------------- */
let signingKey = null;
let publicJwk = null;

async function initKeys() {
  try {
    signingKey = await importPKCS8(PRIVATE_KEY_PEM, 'RS256');
    publicJwk = await exportJWK(signingKey);
    if (!publicJwk.kid) publicJwk.kid = `kid-${uuidv4()}`;
    publicJwk.alg = publicJwk.alg || 'RS256';
    publicJwk.use = 'sig';
    console.log('✅ Signing key loaded; jwk.kid =', publicJwk.kid);
  } catch (err) {
    console.error('[FATAL] Failed to import PRIVATE_KEY_PEM. Ensure it is a valid PKCS#8 PEM.');
    console.error(err && err.message ? err.message : err);
    process.exit(1);
  }
}

/* ---------------------------
   Helper: sign SET / SSF payload
   --------------------------- */
async function signPayload(payload, typ = 'application/secevent+jwt') {
  const now = Math.floor(Date.now() / 1000);
  const jti = uuidv4();
  const body = { ...payload };
  body.iat = body.iat || now;
  body.jti = body.jti || jti;
  body.iss = body.iss || ISS;
  body.aud = body.aud || DEFAULT_AUD;

  const jwt = await new SignJWT(body)
    .setProtectedHeader({ alg: 'RS256', typ })
    .setIssuer(body.iss)
    .setAudience(body.aud)
    .setIssuedAt(body.iat)
    .setJti(body.jti)
    .sign(signingKey);

  return jwt;
}

/* ---------------------------
   CAEP risk-level-change validation helper
   --------------------------- */
function validateCaepRiskChange(setPayload) {
  const errors = [];
  if (!setPayload.iss) errors.push('iss missing');
  if (!setPayload.jti) errors.push('jti missing');
  if (!setPayload.iat) errors.push('iat missing');
  if (!setPayload.events) errors.push('events missing');

  const et = 'https://schemas.openid.net/secevent/caep/event-type/risk-level-change';
  const ev = setPayload.events ? setPayload.events[et] : null;
  if (!ev) errors.push(`events must include ${et}`);
  else {
    if (!ev.principal) errors.push('event.principal missing');
    if (!ev.current_level) errors.push('event.current_level missing');
    const allowed = ['LOW', 'MEDIUM', 'HIGH'];
    if (ev.current_level && !allowed.includes(String(ev.current_level).toUpperCase())) {
      errors.push('current_level must be one of LOW|MEDIUM|HIGH');
    }
  }
  return { valid: errors.length === 0, errors, event: ev };
}

/* ---------------------------
   WELL-KNOWN: JWKS and SSF config
   --------------------------- */
app.get('/.well-known/jwks.json', (req, res) => {
  res.json({ keys: [publicJwk] });
});

app.get('/.well-known/ssf-configuration', (req, res) => {
  res.json({
    issuer: ISS,
    jwks_uri: `${ISS}/.well-known/jwks.json`,
    registration_endpoint: `${ISS}/ssf/streams`,
    status_endpoint: `${ISS}/ssf/status`,
    delivery_methods_supported: ['push'],
    delivery: {
      push: {
        endpoint: `${ISS}/receive`, // recommended endpoint where you accept pushes (not simulated)
        authorization_header: API_TOKEN
      }
    },
    events_supported: [
      'https://schemas.openid.net/secevent/caep/event-type/risk-level-change'
    ],
    authorization_types_supported: ['bearer'],
    signed_set_alg_values_supported: ['RS256'],
    version: '1.0'
  });
});

/* ---------------------------
   Create Stream: POST /ssf/streams
   - body: { receiver_stream_url, events_requested? }
   - builds a signed stream creation SET (events_requested) and POSTs to receiver_stream_url
   - stores returned info (stream_id, delivery endpoint, events_accepted)
   --------------------------- */
app.post('/ssf/streams', async (req, res) => {
  try {
    const receiver_stream_url = req.body.receiver_stream_url || DEFAULT_RECEIVER_URL;
    const eventsRequested = req.body.events_requested || [
      'https://schemas.openid.net/secevent/caep/event-type/risk-level-change'
    ];

    const payload = {
      iss: ISS,
      aud: receiver_stream_url,
      jwks_uri: `${ISS}/.well-known/jwks.json`,
      delivery: {
        method: 'push',
        endpoint: `${ISS}/receive`,
        authorization_header: API_TOKEN
      },
      events_requested: eventsRequested
    };

    const jwt = await signPayload(payload, 'application/secevent+jwt');

    const headers = {
      'Content-Type': 'application/secevent+jwt',
      Accept: 'application/json',
      Authorization: API_TOKEN
    };

    const resp = await axios.post(receiver_stream_url, jwt, { headers, validateStatus: null, timeout: 20000 }).catch(e => e.response || { status: 500, data: String(e) });
    const rdata = resp.data || {};
    const stream_id = rdata.stream_id || uuidv4();
    const deliveryEndpoint = rdata.delivery?.endpoint || DEFAULT_RECEIVER_URL;
    const eventsAccepted = rdata.events_accepted || eventsRequested;
    const status = rdata.status || 'active';

    const streamObj = {
      stream_id,
      receiver_stream_url,
      delivery: { endpoint: deliveryEndpoint },
      events_requested: eventsRequested,
      events_accepted: eventsAccepted,
      status,
      receiver_response: rdata,
      created_at: Date.now()
    };

    streams[stream_id] = streamObj;

    res.json({ message: 'stream create request sent', http_status: resp.status, stream: streamObj, receiver_response: rdata });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err) });
  }
});

/* ---------------------------
   Get Stream: GET /ssf/streams/:id
   --------------------------- */
app.get('/ssf/streams/:id', (req, res) => {
  const id = req.params.id;
  const s = streams[id];
  if (!s) return res.status(404).json({ error: 'stream not found' });
  res.json(s);
});

/* ---------------------------
   Update Stream: POST /ssf/streams/:id
   - body: { receiver_update_url, updates }
   --------------------------- */
app.post('/ssf/streams/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const s = streams[id];
    if (!s) return res.status(404).json({ error: 'stream not found' });

    const receiver_update_url = req.body.receiver_update_url || s.receiver_stream_url;
    const updates = req.body.updates || {}; // e.g., { delivery: { endpoint: "..." } }

    const payload = {
      iss: ISS,
      aud: receiver_update_url,
      stream_id: id,
      updates
    };

    const jwt = await signPayload(payload, 'application/secevent+jwt');
    const headers = { 'Content-Type': 'application/secevent+jwt', Accept: 'application/json', Authorization: API_TOKEN };

    const resp = await axios.post(receiver_update_url, jwt, { headers, validateStatus: null, timeout: 20000 }).catch(e => e.response || { status: 500, data: String(e) });
    const rdata = resp.data || {};

    // if receiver returns updated delivery endpoint / status, reflect locally
    if (rdata.delivery?.endpoint) s.delivery.endpoint = rdata.delivery.endpoint;
    s.status = rdata.status || s.status;
    s.receiver_response = rdata;

    res.json({ message: 'update request sent', http_status: resp.status, stream: s, receiver_response: rdata });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err) });
  }
});

/* ---------------------------
   Delete Stream: POST /ssf/streams/:id/delete
   - body: { receiver_delete_url }
   --------------------------- */
app.post('/ssf/streams/:id/delete', async (req, res) => {
  try {
    const id = req.params.id;
    const s = streams[id];
    if (!s) return res.status(404).json({ error: 'stream not found' });

    const receiver_delete_url = req.body.receiver_delete_url || s.receiver_stream_url;
    const payload = { iss: ISS, aud: receiver_delete_url, stream_id: id, action: 'delete' };

    const jwt = await signPayload(payload, 'application/secevent+jwt');
    const headers = { 'Content-Type': 'application/secevent+jwt', Accept: 'application/json', Authorization: API_TOKEN };

    const resp = await axios.post(receiver_delete_url, jwt, { headers, validateStatus: null, timeout: 20000 }).catch(e => e.response || { status: 500, data: String(e) });
    const rdata = resp.data || {};

    const deleted = rdata.deleted || rdata.status === 'deleted' || resp.status === 200;
    if (deleted) delete streams[id];
    else s.status = rdata.status || s.status;
    s.receiver_response = rdata;

    res.json({ message: 'delete request sent', deleted: !!deleted, http_status: resp.status, receiver_response: rdata });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err) });
  }
});

/* ---------------------------
   Verify Stream: POST /ssf/streams/verify
   - body: { receiver_verify_url }
   --------------------------- */
app.post('/ssf/streams/verify', async (req, res) => {
  try {
    const receiver_verify_url = req.body.receiver_verify_url;
    if (!receiver_verify_url) return res.status(400).json({ error: 'receiver_verify_url required' });

    const payload = { iss: ISS, aud: receiver_verify_url, purpose: 'verify' };
    const jwt = await signPayload(payload, 'application/secevent+jwt');
    const headers = { 'Content-Type': 'application/secevent+jwt', Accept: 'application/json', Authorization: API_TOKEN };

    const resp = await axios.post(receiver_verify_url, jwt, { headers, validateStatus: null, timeout: 15000 }).catch(e => e.response || { status: 500, data: String(e) });
    res.json({ message: 'verify request sent', http_status: resp.status, receiver_response: resp.data || null });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err) });
  }
});

/* ---------------------------
   GET /ssf/status
   - returns local transmitter status (and list of streams summary)
   --------------------------- */
app.get('/ssf/status', (req, res) => {
  const streamSummaries = Object.values(streams).map(s => ({ stream_id: s.stream_id, endpoint: s.delivery.endpoint, status: s.status }));
  res.json({ status: 'active', issuer: ISS, stream_count: streamSummaries.length, streams: streamSummaries, time: new Date().toISOString() });
});

/* ---------------------------
   POST /caep/send-risk-level-change
   - body: { stream_id?, receiver_url?, payload: { principal, current_level, previous_level?, risk_reason?, event_timestamp?, sub_id? } }
   - builds CAEP SET, validates shape, signs and POSTS to target with API_TOKEN header
   --------------------------- */
app.post('/caep/send-risk-level-change', async (req, res) => {
  try {
    const { stream_id, receiver_url, payload } = req.body;
    if (!payload || !payload.principal || !payload.current_level) return res.status(400).json({ error: 'payload with principal and current_level required' });

    const target = receiver_url || (stream_id && streams[stream_id] && streams[stream_id].delivery && streams[stream_id].delivery.endpoint) || DEFAULT_RECEIVER_URL;

    const eventType = 'https://schemas.openid.net/secevent/caep/event-type/risk-level-change';
    const setPayload = {
      iss: ISS,
      aud: payload.aud || DEFAULT_AUD,
      sub_id: payload.sub_id || { format: 'opaque', id: 'unknown' },
      events: {
        [eventType]: {
          principal: payload.principal,
          current_level: String(payload.current_level).toUpperCase(),
          ...(payload.previous_level ? { previous_level: String(payload.previous_level).toUpperCase() } : {}),
          ...(payload.risk_reason ? { risk_reason: payload.risk_reason } : {}),
          ...(payload.event_timestamp ? { event_timestamp: payload.event_timestamp } : {})
        }
      }
    };

    // validate CAEP shape before signing
    const validation = validateCaepRiskChange(Object.assign({}, setPayload, { jti: uuidv4(), iat: Math.floor(Date.now() / 1000) }));
    if (!validation.valid) return res.status(400).json({ error: 'CAEP validation failed', details: validation.errors });

    const signedSET = await signPayload(setPayload, 'application/secevent+jwt');

    const headers = { 'Content-Type': 'application/secevent+jwt', Accept: 'application/json', Authorization: API_TOKEN };
    const resp = await axios.post(target, signedSET, { headers, validateStatus: null, timeout: 20000 }).catch(e => e.response || { status: 500, data: String(e) });

    res.json({ message: 'CAEP SET sent', sent_to: target, http_status: resp.status, receiver_response: resp.data || null });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err) });
  }
});

/* ---------------------------
   Root diagnostics
   --------------------------- */
app.get('/', (req, res) => {
  res.json({
    message: 'CAEP SSF Transmitter - Full API parity (transmitter-only)',
    issuer: ISS,
    jwks: `${ISS}/.well-known/jwks.json`,
    ssf_configuration: `${ISS}/.well-known/ssf-configuration`,
    endpoints: {
      create_stream: '/ssf/streams (POST)',
      get_stream: '/ssf/streams/:id (GET)',
      update_stream: '/ssf/streams/:id (POST)',
      delete_stream: '/ssf/streams/:id/delete (POST)',
      verify_stream: '/ssf/streams/verify (POST)',
      status: '/ssf/status (GET)',
      send_event: '/caep/send-risk-level-change (POST)'
    },
    sample_send_payload: {
      payload: { principal: 'USER', current_level: 'LOW', previous_level: 'HIGH', risk_reason: 'PASSWORD_FOUND_IN_DATA_BREACH' }
    },
    active_streams_count: Object.keys(streams).length
  });
});

/* ---------------------------
   Start server after keys init
   --------------------------- */
initKeys().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 CAEP transmitter (full parity) running on port ${PORT}`);
    console.log(`Discovery: ${ISS}/.well-known/ssf-configuration`);
    console.log(`JWKS: ${ISS}/.well-known/jwks.json`);
  });
}).catch(err => {
  console.error('Key initialization failed:', err);
  process.exit(1);
});
