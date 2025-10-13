// index.js
// CAEP Risk-Level-Change Transmitter for testing (RS256-signed SET / JWT).
// Usage:
//   - set env: PRIVATE_KEY_PEM, ISS, AUD (optional), DEFAULT_TARGET_URL (optional)
//   - start: `node index.js`
// POST /send-risk-change { receiver_url?, authorization?, payload: { sub_id, principal, current_level, previous_level?, risk_reason?, event_timestamp?, initiating_entity?, reason_admin?, reason_user?, txn? } }

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const { SignJWT } = require('jose');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;

const PRIVATE_KEY_PEM = process.env.PRIVATE_KEY_PEM || ''; // PEM including -----BEGIN PRIVATE KEY-----
const ISS = process.env.ISS || 'https://example-transmitter.local/';
const DEFAULT_AUD = process.env.AUD || 'https://sp.example.com/caep';
const DEFAULT_TARGET = process.env.DEFAULT_TARGET_URL || ''; // optional default receiver endpoint

if (!PRIVATE_KEY_PEM) {
  console.warn('WARNING: PRIVATE_KEY_PEM not set. STARTUP still allowed for quick dev but signing will fail at runtime.');
}

function buildSET(payloadClaims = {}) {
  // payloadClaims must include sub_id and required CAEP fields for event.
  const now = Math.floor(Date.now() / 1000);
  const jti = uuidv4();

  // Top level SET (JWT) claims: iss, jti, iat, aud, txn (optional)
  const topClaims = {
    iss: ISS,
    jti,
    iat: now,
    aud: payloadClaims.aud || DEFAULT_AUD
  };
  if (payloadClaims.txn) topClaims.txn = payloadClaims.txn;

  // Construct events object containing the CAEP risk-level-change event
  const events = {};
  const eventType = 'https://schemas.openid.net/secevent/caep/event-type/risk-level-change';

  // Build the event-specific claim object per CAEP 3.8.1
  const caepEvent = {};
  // Required per spec: principal, current_level
  if (!payloadClaims.principal) throw new Error('principal (required) missing in payloadClaims');
  if (!payloadClaims.current_level) throw new Error('current_level (required) missing in payloadClaims');

  caepEvent.principal = payloadClaims.principal; // e.g., "USER" or "DEVICE"
  caepEvent.current_level = payloadClaims.current_level.toUpperCase(); // LOW/MEDIUM/HIGH

  if (payloadClaims.previous_level) caepEvent.previous_level = payloadClaims.previous_level.toUpperCase();
  if (payloadClaims.risk_reason) caepEvent.risk_reason = payloadClaims.risk_reason;
  if (payloadClaims.event_timestamp) caepEvent.event_timestamp = payloadClaims.event_timestamp;
  if (payloadClaims.initiating_entity) caepEvent.initiating_entity = payloadClaims.initiating_entity;
  if (payloadClaims.reason_admin) caepEvent.reason_admin = payloadClaims.reason_admin;
  if (payloadClaims.reason_user) caepEvent.reason_user = payloadClaims.reason_user;

  events[eventType] = caepEvent;

  // Build the final SET payload
  const setPayload = {
    ...topClaims,
    sub_id: payloadClaims.sub_id || { format: 'opaque', id: 'unknown' },
    events
  };

  return { setPayload, jti, iat: now };
}

async function signSET(setPayload) {
  if (!PRIVATE_KEY_PEM) throw new Error('PRIVATE_KEY_PEM env var not set - cannot sign.');

  // Using jose SignJWT to sign with RS256
  const privateKey = await (async () => {
    // create a key from the PEM
    const { importPKCS8 } = require('jose');
    // PRIVATE_KEY_PEM must be PKCS8 PEM (BEGIN PRIVATE KEY) or PKCS1 with conversion
    return importPKCS8(PRIVATE_KEY_PEM, 'RS256');
  })();

  // The "typ" header for SETs can be "application/secevent+jwt" per RFC
  const jwt = await new SignJWT(setPayload)
    .setProtectedHeader({ alg: 'RS256', typ: 'application/secevent+jwt' })
    .setIssuedAt()
    .setIssuer(setPayload.iss)
    .setJti(setPayload.jti)
    .setAudience(setPayload.aud)
    .sign(await privateKey);

  return jwt;
}

// POST /send-risk-change
// Body:
// {
//   "receiver_url": "https://receiver.example.com/ssf/ingest",
//   "authorization": "Bearer ...",      // optional
//   "extra_headers": { "X-Custom": "x" }, // optional
//   "payload": { sub_id: {...}, principal: "USER", current_level: "LOW", ... }
// }
app.post('/send-risk-change', async (req, res) => {
  try {
    const { receiver_url, authorization, extra_headers, payload } = req.body;
    const target = receiver_url || DEFAULT_TARGET;
    if (!target) return res.status(400).json({ error: 'receiver_url missing and DEFAULT_TARGET_URL not configured.' });
    if (!payload) return res.status(400).json({ error: 'payload missing' });

    // Build SET
    const { setPayload } = buildSET(payload);

    // Sign SET (JWT)
    const jwt = await signSET(setPayload);

    // Post to receiver
    const headers = {
      'Content-Type': 'application/secevent+jwt',
      Accept: 'application/json',
      ...extra_headers
    };
    if (authorization) headers.Authorization = authorization;

    const resp = await axios.post(target, jwt, { headers, validateStatus: null, timeout: 20000 });

    // Return receiver status and body for your observability in tests
    res.json({
      forwarded_to: target,
      status: resp.status,
      statusText: resp.statusText,
      response_data: resp.data
    });
  } catch (err) {
    console.error(err.stack || err.toString());
    res.status(500).json({ error: err.message || String(err) });
  }
});

// convenience endpoint to show an example payload and how to call
app.get('/', (req, res) => {
  res.json({
    message: 'CAEP Risk-Level-Change Transmitter (testing). POST to /send-risk-change',
    example: {
      receiver_url: 'https://receiver.example.com/ssf/ingest',
      authorization: 'Bearer <token-if-needed>',
      payload: {
        sub_id: { format: 'iss_sub', iss: 'https://idp.example.com/3456789/', sub: 'jane.doe@example.com' },
        principal: 'USER',
        current_level: 'LOW',
        previous_level: 'HIGH',
        risk_reason: 'PASSWORD_FOUND_IN_DATA_BREACH',
        event_timestamp: Math.floor(Date.now() / 1000),
        txn: '8675309'
      }
    }
  });
});

app.listen(PORT, () => {
  console.log(`CAEP transmitter listening on ${PORT}`);
});
