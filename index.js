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
const FALLBACK_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDk9XSMHCJ4b/Hx\nXQdt9gZ4olLQ2U8TE44y8wNqk8SkZ6d1xqBCSo8a1LOSu5bnFhcif+eRx1tQzjqM\nF1zjvYrO3Z4V8lFvW8EfM+ZtqP8pHcmt+S7RwqTz+qRts4UmtO1FL9HdLQxSgVJg\nq3eYfr6sC6nsVDRL1fZ4RIR4xrIey9c4L0Ryq8iZg4YqE4E3FSmRQvXRmkuKdbP3\nzPA4yl3BfwH0vHtihTmuMZbIMFIl5Ep9ChGLu7f1P1VLqU6D4S2l6upZqW2sX4vA\n3W2Qm2q7uQyqN6hDzB3OG15UqsyUzSyBG4SHoTr2hZeLBfW+uWn1xM0fiGKPve7E\nwlCOXrOFAgMBAAECggEBAJOak+S5hcGgD6PC50rL0W+zAY4kg9It5ahphgm0GOM5\n9qD6XrA6n38GJ6mnUj+CaR6Tu/fqU8ax2UBxNKfr7iDqtxbpg9yY4vlZ2MEXpUGZ\ncbGVbt47mwIRX/y1kzRwrItgglBsqXhFXUt0guKwcn81isHtAEKgsb5vKpkkxPvG\nZpYRx7M3wRv/EZjE6tRKgUK5U7KXYfwMC1hAdgmnRLkG8YQjzqzstJXjU1zHV5hL\nPDUQbXeI3lbEJg4Fkk4efRjeIEJCaRHYp6rgGP0a7Z8J+MQw7tiYnlS6mD7+yVxX\nL6DhzpHeUKptuIZd8OV+nvsr4kslYqpHyR+JHHRP7vECgYEA9G8LWX3ehETrJEdv\nhNfJ9m5s4cYr1GPZWhpZtS3EXA1BrBokxtFSh7yChzYN3QBF0u1VFnMGttJSCwP5\n5B3yGv6SyLPT2ZLtOltuzU4gC6AVnZPKiYh+giFoPAVD4FrHErjRRWvztQXkMqMS\nZLB9d4hklpdRa12AqQAN17zEAK8CgYEA7zTfP00j9o6rKn9Vd0l7nK5Fe9q7w6Gg\nCKgaRIN9EU7AB4EvOC/Da4o+X9vUKakzgrmGtv1P8e8aTFX7ojkZExwl+GLCGLqZ\nYQ5FxyphzDlfh98m+SmU2V6hEtfqgV0MW0fFQWR2Xx91Zk8TzJKpJR2P/41+rkEY\nIsb0pR9AtZ0CgYAwSPMJZ5MN0pMC6vOqO0Z8w08mFnVUsfSC5Al8w8WzOSa0d0r+\nrsA/0HMyWjXGQHkSCmTjrc0H3ydzRZwxOXZPv1VMPKXxQ8D3bEjLk1um2h6yMNZ5\nl4mMLHhLUijG17TfKN8O4Txh9Z5PY0cKJ5AQJ2iOTIuI17WikBt09TLMgQKBgQDK\n1RQlnzTnXPcWZ8ftglpFQ1mVveGycXzYWzsoXyxopJS6oUZsXrAEch8gbE5q4fVA\nIVRz6O2+7VJpUQ2ewO53eOzDqMWd3q11LMmhrb3oH8BeLPNgBDhoNg1KvNKn3Pfr\nk6isyeHQFvXj2DJAlLApD/RtWn+fkyZUEyAykj58EwKBgQCnnR5Z9wFZ1z1tv+/x\nuyGi8iSK9IgeXO5ZPzKWUAcZqR3Dql5LRq3pEG/AnwZmWk6uC8aGXkp9F9yLuyAB\nRvjQ9XxP2r/r1jOa8HtHUR6c1lM6F8w9FDy+e5ZjM8iE4N+6z8chxU4D4m3T3Un5\n0pR2EwHZH3zR1TRyk9PsrT3q8A==\n-----END PRIVATE KEY-----`;

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
