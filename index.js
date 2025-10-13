/**
 * CAEP / SSF Transmitter (final)
 * - Uses Bearer API token for all receiver API calls
 * - Signs all Security Event Tokens (SETs) using RS256
 * - Publishes /.well-known/jwks.json for signature verification
 */

const express = require("express");
const bodyParser = require("body-parser");
const axios = require("axios");
const { SignJWT, importPKCS8, exportJWK } = require("jose");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(bodyParser.json());
const PORT = process.env.PORT || 3000;

// -----------------------------------------------
// 🔐 Configuration (replace for production)
// -----------------------------------------------
const PRIVATE_KEY_PEM = process.env.PRIVATE_KEY_PEM || `
-----BEGIN PRIVATE KEY-----
<replace_with_valid_PKCS8_private_key>
-----END PRIVATE KEY-----
`.trim();

const API_TOKEN = process.env.API_TOKEN || "Bearer my-hardcoded-api-token";
const ISS = process.env.ISS || "https://caep-transmitter-demo.onrender.com/";
const DEFAULT_AUD = process.env.AUD || "https://receiver.example.com/";
const DEFAULT_RECEIVER_URL = process.env.DEFAULT_RECEIVER_URL || "https://webhook.site/your-id";

// In-memory stream store
const streams = {};

// Import private key and export public JWK
let signingKey, publicJwk;
(async () => {
  try {
    signingKey = await importPKCS8(PRIVATE_KEY_PEM, "RS256");
    publicJwk = await exportJWK(signingKey);
    publicJwk.kid = `kid-${uuidv4()}`;
    publicJwk.use = "sig";
    publicJwk.alg = "RS256";
    console.log("✅ Signing key loaded. Public key kid:", publicJwk.kid);
  } catch (err) {
    console.error("[FATAL] Failed to import PRIVATE_KEY_PEM. Ensure it's PKCS#8 PEM format.");
    console.error(err.message);
    process.exit(1);
  }
})();

// Utility: sign payload (SET or SSF object)
async function signJwt(payload, typ = "application/secevent+jwt") {
  const now = Math.floor(Date.now() / 1000);
  payload.iat = now;
  payload.jti = uuidv4();
  payload.iss = payload.iss || ISS;
  payload.aud = payload.aud || DEFAULT_AUD;
  return await new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", typ })
    .setIssuer(payload.iss)
    .setAudience(payload.aud)
    .setIssuedAt(payload.iat)
    .setJti(payload.jti)
    .sign(signingKey);
}

// -----------------------------------------------
// 📡 /.well-known/jwks.json
// -----------------------------------------------
app.get("/.well-known/jwks.json", (req, res) => {
  res.json({ keys: [publicJwk] });
});

// -----------------------------------------------
// 🧩 Create Stream (SSF-compliant)
// -----------------------------------------------
app.post("/create-stream", async (req, res) => {
  try {
    const { receiver_stream_url } = req.body;
    if (!receiver_stream_url) return res.status(400).json({ error: "receiver_stream_url required" });

    const payload = {
      iss: ISS,
      aud: receiver_stream_url,
      events_supported: [
        "https://schemas.openid.net/secevent/caep/event-type/risk-level-change"
      ],
      jwks_uri: `${ISS}.well-known/jwks.json`,
      delivery: {
        method: "push",
        endpoint: `${ISS}receive`,
        authorization_header: API_TOKEN
      }
    };

    const jwt = await signJwt(payload);
    const headers = {
      "Content-Type": "application/secevent+jwt",
      "Accept": "application/json",
      "Authorization": API_TOKEN
    };

    const resp = await axios.post(receiver_stream_url, jwt, { headers, validateStatus: null });
    const stream_id = resp.data?.stream_id || uuidv4();
    const endpoint = resp.data?.delivery?.endpoint || DEFAULT_RECEIVER_URL;
    streams[stream_id] = { stream_id, endpoint, status: resp.data?.status || "active" };

    res.json({
      message: "Stream created successfully (signed + token-authenticated)",
      stream: streams[stream_id],
      receiver_response: resp.data
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -----------------------------------------------
// 🔁 Send CAEP Risk-Level-Change Event
// -----------------------------------------------
app.post("/send-risk-change", async (req, res) => {
  try {
    const { payload, receiver_url, stream_id } = req.body;
    if (!payload?.principal || !payload?.current_level)
      return res.status(400).json({ error: "principal and current_level required" });

    const target =
      receiver_url ||
      (stream_id && streams[stream_id]?.endpoint) ||
      DEFAULT_RECEIVER_URL;

    const eventType =
      "https://schemas.openid.net/secevent/caep/event-type/risk-level-change";
    const setPayload = {
      iss: ISS,
      aud: DEFAULT_AUD,
      sub_id: payload.sub_id || { format: "opaque", id: "unknown" },
      events: {
        [eventType]: {
          principal: payload.principal,
          current_level: payload.current_level.toUpperCase(),
          ...(payload.previous_level && { previous_level: payload.previous_level.toUpperCase() }),
          ...(payload.risk_reason && { risk_reason: payload.risk_reason }),
          ...(payload.event_timestamp && { event_timestamp: payload.event_timestamp })
        }
      }
    };

    const signedSET = await signJwt(setPayload, "application/secevent+jwt");
    const headers = {
      "Content-Type": "application/secevent+jwt",
      "Accept": "application/json",
      "Authorization": API_TOKEN
    };

    const resp = await axios.post(target, signedSET, { headers, validateStatus: null });

    res.json({
      message: "CAEP SET sent successfully",
      sent_to: target,
      http_status: resp.status,
      receiver_response: resp.data
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -----------------------------------------------
// 📥 Receive endpoint (for testing)
// -----------------------------------------------
app.post("/receive", express.text({ type: "*/*" }), (req, res) => {
  console.log("📨 Received SET at /receive");
  console.log("Headers:", req.headers);
  console.log("Body (JWT):", req.body.slice(0, 60) + "...");
  res.json({ message: "SET received successfully", received_bytes: req.body.length });
});

// -----------------------------------------------
// 🧾 Root
// -----------------------------------------------
app.get("/", (req, res) => {
  res.json({
    message: "CAEP SSF Transmitter (signed SETs + API token auth)",
    jwks: `${ISS}.well-known/jwks.json`,
    api_token_used: API_TOKEN.startsWith("Bearer ") ? "Bearer ..." : "none",
    endpoints: {
      create_stream: "/create-stream",
      send_risk_change: "/send-risk-change",
      receive: "/receive"
    }
  });
});

// -----------------------------------------------
app.listen(PORT, () =>
  console.log(`🚀 CAEP transmitter running on port ${PORT}`)
);
