/**
 * CAEP / SSF Transmitter - Full lifecycle + verification + local receiver
 * - Create / Get / Update / Delete Stream (client calls to Receiver endpoints)
 * - Send CAEP risk-level-change events (SET/JWT)
 * - Serve /.well-known/jwks.json (public key) for receivers to verify
 * - /receive endpoint to simulate a receiver (verifies incoming SETs)
 *
 * NOTE: This file contains inline defaults (PRIVATE_KEY_PEM etc.) for convenience/testing.
 * Replace PRIVATE_KEY_PEM before production or move to Render env vars.
 */

const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const { SignJWT, importPKCS8, exportJWK, importJWK, jwtVerify } = require('jose');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');

const app = express();
app.use(bodyParser.json());
const PORT = process.env.PORT || 3000;

/* -------------------------
   DEFAULTS (IN-CODE) — replace for production
   ------------------------- */
/*
  IMPORTANT: For real testing with Jamf/Okta/other receivers you MUST replace this private key
  with your own PKCS#8 RSA private key and keep it secret.
*/
const PRIVATE_KEY_PEM = process.env.PRIVATE_KEY_PEM || `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDkhAZxU4ut1iDd
PvQ0NjA1iYZPbTz4m9W9d6e5yXl8zRjNf3a6Kxy7N7WqkV+gh+HdF7LjSGEoNRt8
sQra6LHgsaom0wKK4GuOPkGcez8zYDPY4Ecy8wKQhBv62hWzBzHbPo8qgx3VGQ4R
iFjH6emEq+YZh8q8hGQGcUSME2YBf8D4Y8bwo4ks1q1OeZQkWApJmA0t6DppzZCk
LsxgXcZjl+Mo0x2KRy5MPzP3LxNQKMMhiA5SL7wzF4nqCjJLM3Q5K9rS/4ZQrm3K
5dEwzT8eZp0/hLb6gTKL3UXT6xwpoZs2T7tfikj/lVwlmC4i5hZ5Eapq0QKBgQDC
rQIDAQABAoIBAQCeB9Uyo3/VH54osVv86J5g4cWrkpF6KZ1M5ICODvE3F1qzV+2r
...REPLACE_WITH_REAL_KEY...
-----END PRIVATE KEY-----
`.trim();

const ISS = process.env.ISS || 'https://caep-transmitter-demo.onrender.com/'; // transmitter issuer URL
const DEFAULT_AUD = process.env.AUD || 'https://receiver.example.com/';
const DEFAULT_RECEIVER_STREAM_URL = process.env.DEFAULT_RECEIVER_STREAM_URL || 'https://webhook.site/your-temp-url';

/* -------------------------
   In-memory store for streams
   key: stream_id -> { stream_id, endpoint, status, receiver_info }
   ------------------------- */
const streams = {};

/* -------------------------
   Initialize signing key & jwk
   Build a public JWK to serve at /.well-known/jwks.json
   ------------------------- */
let signingKey; // jose key object for signing
let publicJwk;  // JWK object to serve

async function initKeys() {
  try {
    signingKey = await importPKCS8(PRIVATE_KEY_PEM, 'RS256'); // private key
    // Export public JWK
    publicJwk = await exportJWK(signingKey);
    // Ensure JWK has a kid for stable referencing
    if (!publicJwk.kid) publicJwk.kid = `kid-${uuidv4()}`;
    publicJwk.use = publicJwk.use || 'sig';
    publicJwk.alg = publicJwk.alg || 'RS256';
    console.log('[INFO] Signing key imported; public JWK prepared with kid:', publicJwk.kid);
  } catch (err) {
    console.error('[FATAL] Failed to import PRIVATE_KEY_PEM. Replace with a valid PKCS#8 PEM.');
    console.error(err);
    process.exit(1);
  }
}

/* -------------------------
   Helper: sign a payload (JWS) with typ header
   typ defaults to 'application/secevent+jwt'
   ------------------------- */
async function signPayload(payload, opts = {}) {
  const typ = opts.typ || 'application/secevent+jwt';
  const now = Math.floor(Date.now() / 1000);
  // Ensure claims exist
  if (!payload.iss) payload.iss = ISS;
  if (!payload.iat) payload.iat = now;
  if (!payload.jti) payload.jti = uuidv4();

  const jwt = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'RS256', typ })
    .setIssuedAt(payload.iat)
    .setIssuer(payload.iss)
    .setJti(payload.jti)
    .setAudience(payload.aud || payload.aud || DEFAULT_AUD)
    .sign(signingKey);
  return jwt;
}

/* -------------------------
   Helper: verify a JWT using a supplied JWKS (or local publicJwk)
   - jwksUri optional: if provided, fetch jwks and use the first key
   - returns { verified: boolean, payload, keyUsed, error }
   ------------------------- */
async function verifyJwt(token, jwksUri) {
  try {
    let jwkToUse = publicJwk;
    if (jwksUri) {
      // fetch remote jwks
      const r = await axios.get(jwksUri, { timeout: 5000 });
      const keys = r.data.keys || (Array.isArray(r.data) ? r.data : null);
      if (!keys || keys.length === 0) throw new Error('No keys found at jwks_uri');
      jwkToUse = keys[0];
    }
    const pubKey = await importJWK(jwkToUse, 'RS256');
    const { payload } = await jwtVerify(token, pubKey, {
      audience: undefined // don't force aud here; caller can check payload.aud
    });
    return { verified: true, payload, keyUsed: jwkToUse };
  } catch (err) {
    return { verified: false, error: err.message || String(err) };
  }
}

/* -------------------------
   CAEP event validation helper
   Validates that a decoded SET payload conforms to CAEP risk-level-change shape:
   - top-level: iss, jti, iat, aud, events
   - events must contain the event type URI for risk-level-change
   - that event object must include 'principal' and 'current_level'
   - Normalize current_level/previous_level to uppercase and check values
   ------------------------- */
function validateCaepRiskLevelChange(setPayload) {
  const errors = [];
  if (!setPayload.iss) errors.push('iss missing');
  if (!setPayload.jti) errors.push('jti missing');
  if (!setPayload.iat) errors.push('iat missing');
  if (!setPayload.events) errors.push('events object missing');

  const eventType = 'https://schemas.openid.net/secevent/caep/event-type/risk-level-change';
  const event = setPayload.events ? setPayload.events[eventType] : null;
  if (!event) errors.push(`events must include key ${eventType}`);
  else {
    if (!event.principal) errors.push('event.principal missing');
    if (!event.current_level) errors.push('event.current_level missing');
    else {
      const level = String(event.current_level).toUpperCase();
      if (!['LOW', 'MEDIUM', 'HIGH'].includes(level)) {
        errors.push('event.current_level must be one of LOW, MEDIUM, HIGH');
      } else {
        event.current_level = level;
      }
    }
    if (event.previous_level) {
      event.previous_level = String(event.previous_level).toUpperCase();
      if (!['LOW', 'MEDIUM', 'HIGH'].includes(event.previous_level)) {
        errors.push('event.previous_level must be one of LOW, MEDIUM, HIGH if present');
      }
    }
  }

  return { valid: errors.length === 0, errors, normalizedEvent: event || null };
}

/* -------------------------
   Endpoint: serve JWKS at /.well-known/jwks.json
   - returns { keys: [ publicJwk ] }
   ------------------------- */
app.get('/.well-known/jwks.json', (req, res) => {
  res.json({ keys: [publicJwk] });
});

/* -------------------------
   Endpoint: Create Stream (SSF-compliant)
   - Request body: { receiver_stream_url, authorization? }
   - Behavior: build a stream-creation JWT per SSF, sign it, POST it to receiver_stream_url
   - Receiver is expected to return JSON { stream_id, status, delivery: { endpoint, ... } }
   - We store stream info locally
   ------------------------- */
app.post('/create-stream', async (req, res) => {
  try {
    const { receiver_stream_url, authorization } = req.body;
    if (!receiver_stream_url) return res.status(400).json({ error: 'receiver_stream_url required' });

    const now = Math.floor(Date.now() / 1000);
    const jti = uuidv4();

    const streamCreate = {
      iss: ISS,
      aud: receiver_stream_url,
      iat: now,
      jti,
      events_supported: [
        'https://schemas.openid.net/secevent/caep/event-type/risk-level-change'
      ],
      jwks_uri: `${ISS}.well-known/jwks.json`,
      delivery: {
        method: 'push',
        endpoint: `${ISS}receive`, // endpoint where receiver will POST events (for this demo we use our /receive)
        authorization_header: 'Bearer transmitter-token'
      }
    };

    const jwt = await signPayload(streamCreate, { typ: 'application/secevent+jwt' });

    const headers = { 'Content-Type': 'application/secevent+jwt', Accept: 'application/json' };
    if (authorization) headers.Authorization = authorization;

    const resp = await axios.post(receiver_stream_url, jwt, { headers, validateStatus: null });

    // Receiver may or may not echo parsed JSON; attempt to parse resp.data
    const rdata = resp.data || {};
    const streamId = rdata.stream_id || uuidv4();
    const deliveryEndpoint = rdata.delivery?.endpoint || DEFAULT_RECEIVER_STREAM_URL;
    const status = rdata.status || 'active';

    const s = {
      stream_id: streamId,
      receiver_registration_url: receiver_stream_url,
      endpoint: deliveryEndpoint,
      status,
      created_at: Date.now(),
      receiver_response: rdata
    };
    streams[streamId] = s;

    res.json({ message: 'stream created', stream: s, raw_response: rdata });
  } catch (err) {
    console.error(err.stack || err);
    res.status(500).json({ error: err.message || String(err) });
  }
});

/* -------------------------
   Endpoint: Get Stream Status
   - GET /stream/:id
   - If we have info locally return it. Also try to GET status from receiver (if receiver supports it)
   ------------------------- */
app.get('/stream/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const s = streams[id];
    if (!s) return res.status(404).json({ error: 'stream not found' });

    // Attempt to ask receiver for status if it provides a status URL in receiver_response
    // Common pattern: receiver might support GET on the stream resource; we try it if available
    let remoteStatus = null;
    try {
      const remoteStatusUrl = s.receiver_response?.status_endpoint || s.receiver_response?.stream_status_url || null;
      if (remoteStatusUrl) {
        const r = await axios.get(remoteStatusUrl, { timeout: 5000 });
        remoteStatus = r.data;
      }
    } catch (e) {
      // ignore remote status fetch errors
      remoteStatus = { error: 'remote status fetch failed', reason: e.message || String(e) };
    }

    res.json({ local: s, remote_status: remoteStatus });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* -------------------------
   Endpoint: Update Stream
   - POST /stream/:id (or PUT)
   - Build a signed update JWT (similar to create), post to receiver's update endpoint
   - Body: { id, receiver_update_url, authorization?, updates: { delivery? , events_supported? } }
   ------------------------- */
app.post('/stream/:id/update', async (req, res) => {
  try {
    const id = req.params.id;
    const s = streams[id];
    if (!s) return res.status(404).json({ error: 'stream not found' });

    const { receiver_update_url, authorization, updates } = req.body;
    if (!receiver_update_url) return res.status(400).json({ error: 'receiver_update_url required' });

    const now = Math.floor(Date.now() / 1000);
    const jti = uuidv4();

    const updatePayload = {
      iss: ISS,
      aud: receiver_update_url,
      iat: now,
      jti,
      stream_id: id,
      updates: updates || {}
    };

    const jwt = await signPayload(updatePayload, { typ: 'application/secevent+jwt' });

    const headers = { 'Content-Type': 'application/secevent+jwt', Accept: 'application/json' };
    if (authorization) headers.Authorization = authorization;

    const resp = await axios.post(receiver_update_url, jwt, { headers, validateStatus: null });

    // reflect changes locally if receiver returns new delivery
    const rdata = resp.data || {};
    if (rdata.delivery?.endpoint) s.endpoint = rdata.delivery.endpoint;
    s.status = rdata.status || s.status;

    res.json({ message: 'update sent', stream: s, receiver_response: rdata });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* -------------------------
   Endpoint: Delete Stream
   - POST /stream/:id/delete
   - Body: { receiver_delete_url, authorization? }
   - Sends a signed deletion request to receiver and removes stream locally on success
   ------------------------- */
app.post('/stream/:id/delete', async (req, res) => {
  try {
    const id = req.params.id;
    const { receiver_delete_url, authorization } = req.body;
    const s = streams[id];
    if (!s) return res.status(404).json({ error: 'stream not found' });
    if (!receiver_delete_url) return res.status(400).json({ error: 'receiver_delete_url required' });

    const now = Math.floor(Date.now() / 1000);
    const jti = uuidv4();

    const deletePayload = {
      iss: ISS,
      aud: receiver_delete_url,
      iat: now,
      jti,
      stream_id: id,
      action: 'delete
