/**
 * CAEP / SSF Transmitter
 * Fully self-contained: stream registration + risk-level-change event
 * Environment variables defined inline for easy Render deployment
 */

const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const { SignJWT, importPKCS8 } = require('jose');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(bodyParser.json());
const PORT = process.env.PORT || 3000;

// 🔧 Hardcoded defaults (override if needed)
const PRIVATE_KEY_PEM = `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC9xxlgmx5N6LrN
SYbR/1LVux0L8nrfu+KoqxFW6nZ2x4bQyixOaFzQ53wNrxhJQXMN3e7yjaZl5bRt
+eUtX3PCbNNyOgl9vPDE+9qvUJ1yp4cg+7rH2XK5Eyy+iySfszZEmmv0RZliMbAo
2by1gqzTz8x4l+AMMzhRZVmK5UyDbkH9L3o0syLe7F7cZJwn2tP76zKQ1Uy8Gk3N
UDFJ3I1FdBxIcrJIlr24pUmD3Vvzt8fAyd2hrSEch9kryZzjK0Ckssu2pMtbUFiE
1/3HhLgT4i6g9TzV9tXnNHFgH4p5Q8+u8Q8P5rXU/lAVmnqPBB3BggVbKTTOYfK5
XcoBtb8hAgMBAAECggEAEXWbC0ChbnvQXlwYZ24aVwcQGRya+2nEWhMoY6Aq5ZAx
...replace-with-real-key...
-----END PRIVATE KEY-----
`;

const ISS = 'https://caep-transmitter-demo.onrender.com/';
const DEFAULT_AUD = 'https://receiver.example.com/';
const DEFAULT_TARGET_URL = 'https://webhook.site/your-temp-url';

// Local store for stream data
let activeStream = null;

// 🛠️ Build + Sign Security Event Token (SET)
async function buildAndSignSET(payload) {
  const now = Math.floor(Date.now() / 1000);
  const jti = uuidv4();

  const eventType = 'https://schemas.openid.net/secevent/caep/event-type/risk-level-change';
  const events = {};
  const caepEvent = {
    principal: payload.principal,
    current_level: payload.current_level.toUpperCase(),
  };
  if (payload.previous_level) caepEvent.previous_level = payload.previous_level.toUpperCase();
  if (payload.risk_reason) caepEvent.risk_reason = payload.risk_reason;
  if (payload.event_timestamp) caepEvent.event_timestamp = payload.event_timestamp;

  events[eventType] = caepEvent;

  const setPayload = {
    iss: ISS,
    aud: payload.aud || DEFAULT_AUD,
    iat: now,
    jti,
    sub_id: payload.sub_id || { format: 'opaque', id: 'unknown' },
    events
  };

  const privateKey = await importPKCS8(PRIVATE_KEY_PEM, 'RS256');
  const jwt = await new SignJWT(setPayload)
    .setProtectedHeader({ alg: 'RS256', typ: 'application/secevent+jwt' })
    .setIssuer(ISS)
    .setAudience(setPayload.aud)
    .setIssuedAt(now)
    .setJti(jti)
    .sign(privateKey);

  return jwt;
}

// 📡 Register Stream per SSF spec
app.post('/register-stream', async (req, res) => {
  try {
    const { receiver_registration_url, authorization } = req.body;
    if (!receiver_registration_url)
      return res.status(400).json({ error: 'receiver_registration_url required' });

    const body = {
      iss: ISS,
      aud: receiver_registration_url,
      events_supported: [
        'https://schemas.openid.net/secevent/caep/event-type/risk-level-change'
      ],
      delivery: {
        method: 'push',
        endpoint: `${ISS}receive`,
        authorization_header: 'Bearer test-transmitter-token'
      }
    };

    const headers = { 'Content-Type': 'application/json' };
    if (authorization) headers.Authorization = authorization;

    const response = await axios.post(receiver_registration_url, body, { headers });
    activeStream = {
      stream_id: response.data.stream_id || uuidv4(),
      endpoint: response.data.delivery?.endpoint || DEFAULT_TARGET_URL,
      status: response.data.status || 'active'
    };

    res.json({
      message: 'Stream registered successfully',
      stream: activeStream,
      receiver_response: response.data
    });
  } catch (err) {
    console.error(err.stack || err);
    res.status(500).json({ error: err.message });
  }
});

// 📨 Send Risk-Level-Change Event
app.post('/send-risk-change', async (req, res) => {
  try {
    const { receiver_url, authorization, payload } = req.body;
    const target = receiver_url || activeStream?.endpoint || DEFAULT_TARGET_URL;
    if (!target)
      return res.status(400).json({ error: 'No receiver_url provided and no active stream found.' });

    const jwt = await buildAndSignSET(payload);

    const headers = {
      'Content-Type': 'application/secevent+jwt',
      Accept: 'application/json'
    };
    if (authorization) headers.Authorization = authorization;

    const resp = await axios.post(target, jwt, { headers, validateStatus: null });
    res.json({
      sent_to: target,
      status: resp.status,
      statusText: resp.statusText,
      receiver_response: resp.data
    });
  } catch (err) {
    console.error(err.stack || err);
    res.status(500).json({ error: err.message });
  }
});

// Root info endpoint
app.get('/', (req, res) => {
  res.json({
    message: '✅ CAEP Transmitter (SSF + Risk-Level-Change) running with built-in defaults.',
    endpoints: {
      register_stream: '/register-stream',
      send_event: '/send-risk-change'
    },
    defaults: {
      ISS,
      DEFAULT_AUD,
      DEFAULT_TARGET_URL
    }
  });
});

app.listen(PORT, () => console.log(`CAEP transmitter running on port ${PORT}`));
