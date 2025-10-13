// index.js
// CAEP / SSF Transmitter — Transmitter-only implementation
// Run: npm install express body-parser axios jose uuid && node index.js

const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const { SignJWT, importPKCS8, exportJWK, importJWK, jwtVerify } = require('jose');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(bodyParser.json());
const PORT = process.env.PORT || 3000;

/* ----------------------
   Configuration (env overrides)
   ---------------------- */
const API_TOKEN = process.env.API_TOKEN || 'Bearer test-api-token-12345';
const ISS = (process.env.ISS || 'http://localhost:3000/').replace(/\/$/, ''); // trim trailing slash
const DEFAULT_AUD = process.env.AUD || 'https://receiver.example.com/';
const DEFAULT_RECEIVER_URL = process.env.DEFAULT_RECEIVER_URL || 'https://webhook.site/<your-webhook-id>';

/* ----------------------
   PRIVATE_KEY_PEM: Try env first, fallback to built-in test key (for local dev).
   Replace PRIVATE_KEY_PEM in production with a secure PKCS#8 PEM (Render env).
   ---------------------- */
const ENV_KEY = process.env.PRIVATE_KEY_PEM && process.env.PRIVATE_KEY_PEM.trim();
const FALLBACK_TEST_PKCS8 = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDk9XSMHCJ4b/Hx
XQdt9gZ4olLQ2U8TE44y8wNqk8SkZ6d1xqBCSo8a1LOSu5bnFhcif+eRx1tQzjqM
F1zjvYrO3Z4V8lFvW8EfM+ZtqP8pHcmt+S7RwqTz+qRts4UmtO1FL9HdLQxSgVJg
q3eYfr6sC6nsVDRL1fZ4RIR4xrIey9c4L0Ryq8iZg4YqE4E3FSmRQvXRmkuKdbP3
zPA4yl3BfwH0vHtihTmuMZbIMFIl5Ep9ChGLu7f1P1VLqU6D4S2l6upZqW2sX4vA
3W2Qm2q7uQyqN6hDzB3OG15UqsyUzSyBG4SHoTr2hZeLBfW+uWn1xM0fiGKPve7E
wlCOXrOFAgMBAAECggEBAJOak+S5hcGgD6PC50rL0W+zAY4kg9It5ahphgm0GOM5
9qD6XrA6n38GJ6mnUj+CaR6Tu/fqU8ax2UBxNKfr7iDqtxbpg9yY4vlZ2MEXpUGZ
cbGVbt47mwIRX/y1kzRwrItgglBsqXhFXUt0guKwcn81isHtAEKgsb5vKpkkxPvG
ZpYRx7M3wRv/EZjE6tRKgUK5U7KXYfwMC1hAdgmnRLkG8YQjzqzstJXjU1zHV5hL
PDUQbXeI3lbEJg4Fkk4efRjeIEJCaRHYp6rgGP0a7Z8J+MQw7tiYnlS6mD7+yVxX
L6DhzpHeUKptuIZd8OV+nvsr4kslYqpHyR+JHHRP7vECgYEA9G8LWX3ehETrJEdv
hNfJ9m5s4cYr1GPZWhpZtS3EXA1BrBokxtFSh7yChzYN3QBF0u1VFnMGttJSCwP5
5B3yGv6SyLPT2ZLtOltuzU4gC6AVnZPKiYh+giFoPAVD4FrHErjRRWvztQXkMqMS
ZLB9d4hklpdRa12AqQAN17zEAK8CgYEA7zTfP00j9o6rKn9Vd0l7nK5Fe9q7w6Gg
CKgaRIN9EU7AB4EvOC/Da4o+X9vUKakzgrmGtv1P8e8aTFX7ojkZExwl+GLCGLqZ
YQ5FxyphzDlfh98m+SmU2V6hEtfqgV0MW0fFQWR2Xx91Zk8TzJKpJR2P/41+rkEY
Isb0pR9AtZ0CgYAwSPMJZ5MN0pMC6vOqO0Z8w08mFnVUsfSC5Al8w8WzOSa0d0r+
rsA/0HMyWjXGQHkSCmTjrc0H3ydzRZwxOXZPv1VMPKXxQ8D3bEjLk1um2h6yMNZ5
l4mMLHhLUijG17TfKN8O4Txh9Z5PY0cKJ5AQJ2iOTIuI17WikBt09TLMgQKBgQDK
1RQlnzTnXPcWZ8ftglpFQ1mVveGycXzYWzsoXyxopJS6oUZsXrAEch8gbE5q4fVA
IVRz6O2+7VJpUQ2ewO53eOzDqMWd3q11LMmhrb3oH8BeLPNgBDhoNg1KvNKn3Pfr
k6isyeHQFvXj2DJAlLApD/RtWn+fkyZUEyAykj58EwKBgQCnnR5Z9wFZ1z1tv+/x
uyGi8iSK9IgeXO5ZPzKWUAcZqR3Dql5LRq3pEG/AnwZmWk6uC8aGXkp9F9yLuyAB
RvjQ9XxP2r/r1jOa8HtHUR6c1lM6F8w9FDy+e5ZjM8iE4N+6z8chxU4D4m3T3Un5
0pR2EwHZH3zR1TRyk9PsrT3q8A==\n-----END PRIVATE KEY-----`;

const PRIVATE_KEY_PEM = ENV_KEY || FALLBACK_TEST_PKCS8;

/* ----------------------
   In-memory streams store
   { stream_id: { stream_id, receiver_stream_url, delivery: {endpoint,...}, events_accepted, status, created_at, receiver_response } }
   ---------------------- */
const streams = {};

/* ----------------------
   JOSE key init
   ---------------------- */
let signingKeyObj = null;
let publicJwk = null;

async function initKeys() {
  try {
    signingKeyObj = await importPKCS8(PRIVATE_KEY_PEM, 'RS256');
    publicJwk = await exportJWK(signingKeyObj);
    if (!publicJwk.kid) publicJwk.kid = `kid-${uuidv4()}`;
    publicJwk.alg = publicJwk.alg || 'RS256';
    publicJwk.use = publicJwk.use || 'sig';
    console.log('✅ Signing key loaded; jwk.kid =', publicJwk.kid);
  } catch (err) {
    console.error('[FATAL] Failed to import PRIVATE_KEY_PEM. Ensure it is a valid PKCS#8 PEM.');
    console.error(err && err.message ? err.message : err);
    process.exit(1);
  }
}

/* ----------------------
   Helpers
   ---------------------- */
async function signPayload(payload, typ = 'application/secevent+jwt') {
  const now = Math.floor(Date.now() / 1000);
  const jti = uuidv4();
  const body = Object.assign({}, payload);
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
    .sign(signingKeyObj);

  return jwt;
}

function caepValidateRiskChange(payload) {
  const errors = [];
  if (!payload.iss) errors.push('iss missing');
  if (!payload.jti) errors.push('jti missing');
  if (!payload.iat) errors.push('iat missing');

  if (!payload.events) errors.push('events missing');
  const et = 'https://schemas.openid.net/secevent/caep/event-type/risk-level-change';
  const ev = payload.events ? payload.events[et] : null;
  if (!ev) errors.push(`events must include ${et}`);
  else {
    if (!ev.principal) errors.push('event.principal missing');
    if (!ev.current_level) errors.push('event.current_level missing');
    const ok = ['LOW', 'MEDIUM', 'HIGH'];
    if (ev.current_level && !ok.includes(String(ev.current_level).toUpperCase())) {
      errors.push('current_level must be LOW, MEDIUM, or HIGH');
    }
  }
  return { valid: errors.length === 0, errors, event: ev };
}

/* ----------------------
   /.well-known/jwks.json
   ---------------------- */
app.get('/.well-known/jwks.json', (req, res) => {
  res.json({ keys: [publicJwk] });
});

/* ----------------------
   /.well-known/ssf-configuration
   ---------------------- */
app.get('/.well-known/ssf-configuration', (req, res) => {
  res.json({
    issuer: ISS,
    jwks_uri: `${ISS}/.well-known/jwks.json`,
    registration_endpoint: `${ISS}/ssf/streams`,    // create stream
    status_endpoint: `${ISS}/ssf/status`,
    delivery_methods_supported: ['push'],
    delivery: {
      push: {
        endpoint: `${ISS}/receive`,
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

/* ----------------------
   Create Stream (POST /ssf/streams)
   - body: { receiver_stream_url }
   - constructs a signed "stream create" SET with events_requested
   - posts it to receiver_stream_url (with Authorization: API_TOKEN)
   - stores local stream object using returned stream_id (or generated UUID)
   ---------------------- */
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

    const s = {
      stream_id,
      receiver_stream_url,
      delivery: { endpoint: deliveryEndpoint },
      events_requested: eventsRequested,
      events_accepted: eventsAccepted,
      status,
      receiver_response: rdata,
      created_at: Date.now()
    };
    streams[stream_id] = s;

    res.json({ message: 'stream created (request sent)', stream: s, receiver_response: rdata, http_status: resp.status });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err) });
  }
});

/* ----------------------
   Get Stream (GET /ssf/streams/:id)
   ---------------------- */
app.get('/ssf/streams/:id', (req, res) => {
  const id = req.params.id;
  const s = streams[id];
  if (!s) return res.status(404).json({ error: 'stream not found' });
  res.json(s);
});

/* ----------------------
   Update Stream (POST /ssf/streams/:id)
   - body: { receiver_update_url, updates }
   - sends a signed update JWT to receiver_update_url
   ---------------------- */
app.post('/ssf/streams/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const s = streams[id];
    if (!s) return res.status(404).json({ error: 'stream not found' });

    const receiver_update_url = req.body.receiver_update_url || s.receiver_stream_url;
    const updates = req.body.updates || {};

    const payload = {
      iss: ISS,
      aud: receiver_update_url,
      stream_id: id,
      updates
    };

    const jwt = await signPayload(payload, 'application/secevent+jwt');
    const headers = {
      'Content-Type': 'application/secevent+jwt',
      Accept: 'application/json',
      Authorization: API_TOKEN
    };

    const resp = await axios.post(receiver_update_url, jwt, { headers, validateStatus: null, timeout: 20000 }).catch(e => e.response || { status: 500, data: String(e) });
    const rdata = resp.data || {};
    // update local record if receiver returns delivery endpoint or status
    if (rdata.delivery?.endpoint) s.delivery.endpoint = rdata.delivery.endpoint;
    s.status = rdata.status || s.status;
    s.receiver_response = rdata;

    res.json({ message: 'update request sent', stream: s, receiver_response: rdata, http_status: resp.status });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err) });
  }
});

/* ----------------------
   Delete Stream (POST /ssf/streams/:id/delete)
   - body: { receiver_delete_url }
   ---------------------- */
app.post('/ssf/streams/:id/delete', async (req, res) => {
  try {
    const id = req.params.id;
    const s = streams[id];
    if (!s) return res.status(404).json({ error: 'stream not found' });

    const receiver_delete_url = req.body.receiver_delete_url || s.receiver_stream_url;

    const payload = {
      iss: ISS,
      aud: receiver_delete_url,
      stream_id: id,
      action: 'delete'
    };

    const jwt = await signPayload(payload, 'application/secevent+jwt');
    const headers = { 'Content-Type': 'application/secevent+jwt', Accept: 'application/json', Authorization: API_TOKEN };

    const resp = await axios.post(receiver_delete_url, jwt, { headers, validateStatus: null, timeout: 20000 }).catch(e => e.response || { status: 500, data: String(e) });
    const rdata = resp.data || {};
    const deleted = rdata.deleted || rdata.status === 'deleted' || resp.status === 200;
    if (deleted) delete streams[id];
    else s.status = rdata.status || s.status;
    s.receiver_response = rdata;

    res.json({ message: 'delete request sent', deleted: !!deleted, receiver_response: rdata, http_status: resp.status });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err) });
  }
});

/* ----------------------
   Verify Stream (POST /ssf/streams/verify)
   - body: { receiver_verify_url }
   - builds a signed small JWT verifying point-of-contact; POSTs to receiver_verify_url
   ---------------------- */
app.post('/ssf/streams/verify', async (req, res) => {
  try {
    const receiver_verify_url = req.body.receiver_verify_url;
    if (!receiver_verify_url) return res.status(400).json({ error: 'receiver_verify_url required' });

    const payload = {
      iss: ISS,
      aud: receiver_verify_url,
      purpose: 'verify'
    };

    const jwt = await signPayload(payload, 'application/secevent+jwt');
    const headers = { 'Content-Type': 'application/secevent+jwt', Accept: 'application/json', Authorization: API_TOKEN };
    const resp = await axios.post(receiver_verify_url, jwt, { headers, validateStatus: null, timeout: 15000 }).catch(e => e.response || { status: 500, data: String(e) });

    res.json({ message: 'verify request sent', receiver_response: resp.data || null, http_status: resp.status });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err) });
  }
});

/* ----------------------
   POST /caep/send-risk-level-change
   - body: { stream_id?, receiver_url?, payload: { principal, current_level, previous_level?, risk_reason?, event_timestamp?, sub_id? } }
   - signs a CAEP SET (RS256) and POSTs to target (stream.delivery.endpoint or receiver_url)
   ---------------------- */
app.post('/caep/send-risk-level-change', async (req, res) => {
  try {
    const { stream_id, receiver_url, payload } = req.body;
    if (!payload || !payload.principal || !payload.current_level) {
      return res.status(400).json({ error: 'payload with principal and current_level required' });
    }

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

    // Validate CAEP shape before signing
    const validation = caepValidateRiskChange(Object.assign({}, setPayload, { jti: uuidv4(), iat: Math.floor(Date.now() / 1000) }));
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

/* ----------------------
   Small debug root + stream list
   ---------------------- */
app.get('/', (req, res) => {
  res.json({
    message: 'CAEP SSF Transmitter (transmitter-only). Use /ssf/streams to create streams and /caep/send-risk-level-change to send events.',
    endpoints: {
      ssf_configuration: '/.well-known/ssf-configuration',
      jwks: '/.well-known/jwks.json',
      create_stream: '/ssf/streams (POST)',
      get_stream: '/ssf/streams/:id',
      update_stream: '/ssf/streams/:id (POST)',
      delete_stream: '/ssf/streams/:id/delete (POST)',
      verify_stream: '/ssf/streams/verify (POST)',
      send_event: '/caep/send-risk-level-change (POST)'
    },
    sample_send_payload: {
      payload: { principal: 'USER', current_level: 'LOW', previous_level: 'HIGH', risk_reason: 'PASSWORD_FOUND_IN_DATA_BREACH' }
    },
    active_streams_count: Object.keys(streams).length
  });
});

/* ----------------------
   Start after key init
   ---------------------- */
initKeys().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 CAEP transmitter (transmitter-only) running on port ${PORT}`);
    console.log(`Discovery: ${ISS}/.well-known/ssf-configuration`);
    console.log(`JWKS: ${ISS}/.well-known/jwks.json`);
  });
}).catch(err => {
  console.error('Key init failed', err);
  process.exit(1);
});
