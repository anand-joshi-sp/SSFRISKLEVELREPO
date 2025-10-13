require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const { SignJWT, importPKCS8 } = require('jose');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;

// ---------- DEFAULTS (used if not provided by Render env) ----------
const DEFAULT_PRIVATE_KEY_PEM = `
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDkhAZxU4ut1iDd
PvQ0NjA1iYZPbTz4m9W9d6e5yXl8zRjNf3a6Kxy7N7WqkV+gh+HdF7LjSGEoNRt8
sQra6LHgsaom0wKK4GuOPkGcez8zYDPY4Ecy8wKQhBv62hWzBzHbPo8qgx3VGQ4R
iFjH6emEq+YZh8q8hGQGcUSME2YBf8D4Y8bwo4ks1q1OeZQkWApJmA0t6DppzZCk
LsxgXcZjl+Mo0x2KRy5MPzP3LxNQKMMhiA5SL7wzF4nqCjJLM3Q5K9rS/4ZQrm3K
5dEwzT8eZp0/hLb6gTKL3UXT6xwpoZs2T7tfikj/lVwlmC4i5hZ5Eapq0QKBgQDC
rQIDAQABAoIBAQCeB9Uyo3/VH54osVv86J5g4cWrkpF6KZ1M5ICODvE3F1qzV+2r
...replace-with-your-real-key...
-----END PRIVATE KEY-----
`;

const PRIVATE_KEY_PEM = process.env.PRIVATE_KEY_PEM || DEFAULT_PRIVATE_KEY_PEM.trim();
const ISS = process.env.ISS || 'https://caep-transmitter-demo.onrender.com/';
const AUD = process.env.AUD || 'https://receiver.example.com/ssf';
const DEFAULT_TARGET = process.env.DEFAULT_TARGET_URL || 'https://receiver.example.com/ssf/ingest';
// --------------------------------------------------------------------

function buildSET(payload) {
  const now = Math.floor(Date.now() / 1000);
  const jti = uuidv4();

  if (!payload.principal) throw new Error('Missing required principal');
  if (!payload.current_level) throw new Error('Missing required current_level');

  const eventType = 'https://schemas.openid.net/secevent/caep/event-type/risk-level-change';
  const caepEvent = {
    principal: payload.principal,
    current_level: payload.current_level.toUpperCase(),
  };
  if (payload.previous_level) caepEvent.previous_level = payload.previous_level.toUpperCase();
  if (payload.risk_reason) caepEvent.risk_reason = payload.risk_reason;
  if (payload.event_timestamp) caepEvent.event_timestamp = payload.event_timestamp;

  const events = {};
  events[eventType] = caepEvent;

  const setPayload = {
    iss: ISS,
    aud: payload.aud || AUD,
    iat: now,
    jti,
    sub_id: payload.sub_id || { format: 'opaque', id: 'unknown' },
    events,
  };

  return setPayload;
}

async function signSET(payload) {
  const privateKey = await importPKCS8(PRIVATE_KEY_PEM, 'RS256');
  const jwt = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'RS256', typ: 'application/secevent+jwt' })
    .setIssuer(payload.iss)
    .setAudience(payload.aud)
    .setIssuedAt()
    .setJti(payload.jti)
    .sign(privateKey);
  return jwt;
}

app.post('/send-risk-change', async (req, res) => {
  try {
    const { receiver_url, authorization, extra_headers, payload } = req.body;
    const target = receiver_url || DEFAULT_TARGET;

    const setPayload = buildSET(payload);
    const jwt = await signSET(setPayload);

    const headers = {
      'Content-Type': 'application/secevent+jwt',
      Accept: 'application/json',
      ...extra_headers,
    };
    if (authorization) headers.Authorization = authorization;

    const resp = await axios.post(target, jwt, { headers, validateStatus: null });
    res.json({
      forwarded_to: target,
      status: resp.status,
      response: resp.data,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/', (req, res) => {
  res.json({
    message: 'CAEP Risk-Level-Change transmitter running.',
    example_curl:
      'curl -X POST https://your-service.onrender.com/send-risk-change -H "Content-Type: application/json" -d \'{"payload":{"principal":"USER","current_level":"LOW"}}\'',
  });
});

app.listen(PORT, () => console.log(`CAEP transmitter running on ${PORT}`));
