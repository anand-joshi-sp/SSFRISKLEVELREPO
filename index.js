/**
 * Spec-compliant CAEP / SSF Transmitter (transmitter-only)
 * - Reads PKCS#8 private key from ./private_key_pkcs8.pem (required)
 * - Supports CAEP complex SET payloads (nested sub_id, arbitrary events)
 * - /.well-known/ssf-configuration & /.well-known/jwks.json
 * - /ssf/streams (register/update/delete)
 * - /ssf/status (status summary)
 * - /caep/send-generic (send any CAEP event, including your complex format)
 */

const fs = require("fs");
const path = require("path");
const express = require("express");
const bodyParser = require("body-parser");
const axios = require("axios");
const { SignJWT, importPKCS8, exportJWK } = require("jose");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(bodyParser.json({ limit: "2mb" }));

/* ---------- Configuration ---------- */
const PORT = process.env.PORT || 3000;
const ISS = (process.env.ISS || "https://ssfrisklevelrepo.onrender.com").replace(/\/$/, "");
const BEARER_TOKEN = "Bearer token123";

/* ---------- Load Private Key ---------- */
const KEY_PATH = path.join(__dirname, "private_key_pkcs8.pem");
if (!fs.existsSync(KEY_PATH)) {
  console.error("❌ Missing private_key_pkcs8.pem");
  process.exit(1);
}
const PRIVATE_KEY_PEM = fs.readFileSync(KEY_PATH, "utf8");

/* ---------- Initialize Key ---------- */
let signingKey, publicJwk;
async function initKeys() {
  signingKey = await importPKCS8(PRIVATE_KEY_PEM, "RS256");
  publicJwk = await exportJWK(signingKey);
  publicJwk.kid = publicJwk.kid || `kid-${uuidv4()}`;
  publicJwk.use = "sig";
  publicJwk.alg = "RS256";
  console.log("✅ Key ready, kid =", publicJwk.kid);
}

/* ---------- Sign helper ---------- */
async function signSET(payload) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", typ: "secevent+jwt", kid: publicJwk.kid })
    .setIssuedAt(payload.iat || now)
    .setIssuer(payload.iss || ISS)
    .setAudience(payload.aud)
    .setJti(payload.jti || uuidv4())
    .sign(signingKey);
}

/* ---------- Memory store ---------- */
const streams = {};

/* ---------- Well-known ---------- */
app.get("/.well-known/jwks.json", (req, res) => res.json({ keys: [publicJwk] }));
app.get("/.well-known/ssf-configuration", (req, res) => {
  res.json({
    issuer: ISS,
    delivery_methods_supported: ["urn:ietf:rfc:8935", "urn:ietf:rfc:8936"],
    configuration_endpoint: `${ISS}/ssf/streams`,
    status_endpoint: `${ISS}/ssf/status`,
    verification_endpoint: `${ISS}/ssf/streams/verify`,
    jwks_uri: `${ISS}/.well-known/jwks.json`,
    spec_version: "1_0-ID2",
    authorization_schemes: [{ spec_urn: "urn:ietf:rfc:6749" }]
  });
});

/* ---------- Auth middleware ---------- */
app.use("/ssf", (req, res, next) => {
  if (req.headers.authorization !== BEARER_TOKEN)
    return res.status(401).json({ error: "unauthorized" });
  next();
});

/* ---------- Stream Management ---------- */
app.post("/ssf/streams", (req, res) => {
  const body = req.body || {};
  const delivery = body.delivery || {};
  if (!delivery.endpoint && !delivery.endpoint_url)
    return res.status(400).json({ error: "invalid_delivery" });
  const id = uuidv4();
  const now = new Date().toISOString();
  const stream = {
    stream_id: id,
    iss: body.iss,
    aud: body.aud,
    jwks_uri: body.jwks_uri || `${ISS}/.well-known/jwks.json`,
    delivery: {
      method: delivery.method || "urn:ietf:rfc:8935",
      endpoint: delivery.endpoint || delivery.endpoint_url,
      authorization_header: delivery.authorization_header || BEARER_TOKEN
    },
    events_requested: body.events_requested || [],
    events_accepted: body.events_requested || [],
    events_delivered: body.events_requested || [],
    description: body.description || null,
    status: "enabled",
    created_at: now,
    updated_at: now
  };
  streams[id] = stream;
  res.status(201).json(stream);
});

app.get("/ssf/streams/:id", (req, res) => {
  const s = streams[req.params.id];
  if (!s) return res.status(404).json({ error: "stream_not_found" });
  res.json(s);
});

app.patch("/ssf/streams/:id", (req, res) => {
  const s = streams[req.params.id];
  if (!s) return res.status(404).json({ error: "stream_not_found" });
  Object.assign(s, req.body, { updated_at: new Date().toISOString() });
  res.json(s);
});

app.post("/ssf/streams/:id/delete", (req, res) => {
  if (!streams[req.params.id]) return res.status(404).json({ error: "stream_not_found" });
  delete streams[req.params.id];
  res.status(204).send();
});

/* ---------- SSF Status (only) ---------- */
app.get("/ssf/status", (req, res) => {
  const summary = Object.values(streams).map(s => ({
    stream_id: s.stream_id,
    endpoint: s.delivery.endpoint,
    status: s.status
  }));
  res.status(200).json({
    status: "active",
    count: summary.length,
    streams: summary,
    timestamp: new Date().toISOString(),
    issuer: ISS
  });
});

/**
 * POST /caep/send-generic
 * Send CAEP/SSF event (supports nested complex payloads)
 * Always delivers to a registered stream.
 *
 * Body:
 * {
 *   "stream_id": "<registered stream_id>",
 *   "payload": { ... full SET payload ... }
 * }
 */
app.post("/caep/send-generic", async (req, res) => {
  try {
    const { stream_id, payload } = req.body || {};

    if (!stream_id) {
      return res.status(400).json({ error: "stream_id_required" });
    }
    const s = streams[stream_id];
    if (!s) {
      return res.status(404).json({ error: "stream_not_found" });
    }
    if (s.status !== "enabled") {
      return res.status(400).json({ error: "stream_not_active" });
    }

    if (!payload || typeof payload !== "object") {
      return res.status(400).json({ error: "invalid_payload" });
    }

    // Sign the payload as-is (complex structures allowed)
    const signed = await signSET(payload);

    const headers = {
      "Content-Type": "secevent+jwt",
      Authorization: s.delivery.authorization_header || BEARER_TOKEN
    };

    console.log(`📤 Sending SET to ${s.delivery.endpoint} for stream ${stream_id}`);

    const resp = await axios.post(s.delivery.endpoint, signed, {
      headers,
      validateStatus: () => true,
      timeout: 20000
    });

    const status = resp.status || 0;
    console.log(`✅ Delivered SET to ${s.delivery.endpoint} [${status}]`);

    // Track events delivered (CAEP spec field)
    s.events_delivered = s.events_delivered || [];
    s.events_delivered.push(Object.keys(payload.events || {}));
    s.updated_at = new Date().toISOString();

    res.status(200).json({
      message: "sent",
      http_status: status,
      stream_id,
      receiver_response: resp.data || null
    });
  } catch (err) {
    console.error("❌ send-generic error:", err.message);
    res.status(500).json({ error: "internal_error", message: err.message });
  }
});

/* ---------- Root ---------- */
app.get("/", (req, res) =>
  res.json({
    message: "CAEP/SSF Transmitter",
    discovery: `${ISS}/.well-known/ssf-configuration`,
    status: `${ISS}/ssf/status`
  })
);

/* ---------- Start ---------- */
initKeys().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Transmitter running on ${PORT}`);
    console.log(`Discovery: ${ISS}/.well-known/ssf-configuration`);
  });
});
