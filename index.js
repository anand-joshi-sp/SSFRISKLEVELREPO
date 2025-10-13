/**
 * CAEP / SSF Transmitter - Full API parity (transmitter-only)
 * Author: Anand-friendly build
 */

const fs = require("fs");
const path = require("path");
const express = require("express");
const bodyParser = require("body-parser");
const axios = require("axios");
const { SignJWT, importPKCS8, exportJWK } = require("jose");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(bodyParser.json());

/* ---------- Configuration ---------- */
const PORT = process.env.PORT || 3000;
const API_TOKEN = process.env.API_TOKEN || "Bearer test-api-token-12345";
const ISS = (process.env.ISS || `http://localhost:${PORT}`).replace(/\/$/, "");
const DEFAULT_AUD = process.env.AUD || "https://receiver.example.com/";
const DEFAULT_RECEIVER_URL =
  process.env.DEFAULT_RECEIVER_URL || "https://webhook.site/<your-webhook-id>";

/* ---------- Load Private Key from PEM ---------- */
let PRIVATE_KEY_PEM;
try {
  const keyPath = path.join(__dirname, "private_key_pkcs8.pem");
  PRIVATE_KEY_PEM = fs.readFileSync(keyPath, "utf8");
  console.log(`🔑 Loaded private key from ${keyPath}`);
} catch (err) {
  console.error("❌ private_key_pkcs8.pem missing or unreadable. Generate it with OpenSSL.");
  process.exit(1);
}

/* ---------- Import key ---------- */
let signingKey, publicJwk;
async function initKeys() {
  try {
    signingKey = await importPKCS8(PRIVATE_KEY_PEM, "RS256");
    publicJwk = await exportJWK(signingKey);
    publicJwk.kid = `kid-${uuidv4()}`;
    publicJwk.use = "sig";
    publicJwk.alg = "RS256";
    console.log("✅ Signing key loaded; kid =", publicJwk.kid);
  } catch (err) {
    console.error("[FATAL] Failed to import PRIVATE_KEY_PEM:", err.message);
    process.exit(1);
  }
}

/* ---------- Helper: sign payload ---------- */
async function signPayload(payload, typ = "application/secevent+jwt") {
  const now = Math.floor(Date.now() / 1000);
  return await new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", typ })
    .setIssuedAt(now)
    .setIssuer(ISS)
    .setAudience(payload.aud || DEFAULT_AUD)
    .setJti(uuidv4())
    .sign(signingKey);
}

/* ---------- Data store ---------- */
const streams = {};

/* ---------- WELL-KNOWN endpoints ---------- */
app.get("/.well-known/jwks.json", (req, res) => res.json({ keys: [publicJwk] }));

app.get("/.well-known/ssf-configuration", (req, res) => {
  res.json({
    issuer: ISS,
    jwks_uri: `${ISS}/.well-known/jwks.json`,
    registration_endpoint: `${ISS}/ssf/streams`,
    status_endpoint: `${ISS}/ssf/status`,
    delivery_methods_supported: ["push"],
    delivery: {
      push: { endpoint: `${ISS}/receive`, authorization_header: API_TOKEN },
    },
    events_supported: [
      "https://schemas.openid.net/secevent/caep/event-type/risk-level-change",
    ],
    authorization_types_supported: ["bearer"],
    signed_set_alg_values_supported: ["RS256"],
    version: "1.0",
  });
});

/* ---------- Stream CRUD ---------- */
app.post("/ssf/streams", async (req, res) => {
  const receiver = req.body.receiver_stream_url || DEFAULT_RECEIVER_URL;
  const payload = {
    iss: ISS,
    aud: receiver,
    jwks_uri: `${ISS}/.well-known/jwks.json`,
    delivery: { method: "push", endpoint: `${ISS}/receive`, authorization_header: API_TOKEN },
    events_requested: [
      "https://schemas.openid.net/secevent/caep/event-type/risk-level-change",
    ],
  };
  const jwt = await signPayload(payload);
  const headers = { "Content-Type": "application/secevent+jwt", Authorization: API_TOKEN };
  const resp = await axios.post(receiver, jwt, { headers, validateStatus: () => true });
  const id = uuidv4();
  streams[id] = { id, receiver, status: "active" };
  res.json({ message: "Stream create sent", http_status: resp.status, id });
});

app.get("/ssf/streams/:id", (req, res) => {
  const s = streams[req.params.id];
  if (!s) return res.status(404).json({ error: "stream not found" });
  res.json(s);
});

app.post("/ssf/streams/:id", async (req, res) => {
  const s = streams[req.params.id];
  if (!s) return res.status(404).json({ error: "stream not found" });
  const payload = { iss: ISS, aud: s.receiver, stream_id: s.id, updates: req.body };
  const jwt = await signPayload(payload);
  const headers = { "Content-Type": "application/secevent+jwt", Authorization: API_TOKEN };
  const resp = await axios.post(s.receiver, jwt, { headers, validateStatus: () => true });
  res.json({ message: "Stream update sent", http_status: resp.status });
});

app.post("/ssf/streams/:id/delete", async (req, res) => {
  const s = streams[req.params.id];
  if (!s) return res.status(404).json({ error: "stream not found" });
  const payload = { iss: ISS, aud: s.receiver, stream_id: s.id, action: "delete" };
  const jwt = await signPayload(payload);
  const headers = { "Content-Type": "application/secevent+jwt", Authorization: API_TOKEN };
  const resp = await axios.post(s.receiver, jwt, { headers, validateStatus: () => true });
  delete streams[s.id];
  res.json({ message: "Stream deleted", http_status: resp.status });
});

app.post("/ssf/streams/verify", async (req, res) => {
  const receiver = req.body.receiver_verify_url || DEFAULT_RECEIVER_URL;
  const payload = { iss: ISS, aud: receiver, purpose: "verify" };
  const jwt = await signPayload(payload);
  const headers = { "Content-Type": "application/secevent+jwt", Authorization: API_TOKEN };
  const resp = await axios.post(receiver, jwt, { headers, validateStatus: () => true });
  res.json({ message: "Verify request sent", http_status: resp.status });
});

/* ---------- Send CAEP event ---------- */
app.post("/caep/send-risk-level-change", async (req, res) => {
  const p = req.body.payload || {};
  const target = req.body.receiver_url || DEFAULT_RECEIVER_URL;
  const eventType =
    "https://schemas.openid.net/secevent/caep/event-type/risk-level-change";
  const set = {
    iss: ISS,
    aud: DEFAULT_AUD,
    events: {
      [eventType]: {
        principal: p.principal || "USER",
        current_level: (p.current_level || "LOW").toUpperCase(),
        previous_level: (p.previous_level || "HIGH").toUpperCase(),
        risk_reason: p.risk_reason || "PASSWORD_FOUND_IN_DATA_BREACH",
      },
    },
  };
  const jwt = await signPayload(set);
  const headers = { "Content-Type": "application/secevent+jwt", Authorization: API_TOKEN };
  const resp = await axios.post(target, jwt, { headers, validateStatus: () => true });
  res.json({ message: "CAEP event sent", http_status: resp.status });
});

/* ---------- Status ---------- */
app.get("/ssf/status", (req, res) => {
  res.json({
    status: "active",
    stream_count: Object.keys(streams).length,
    time: new Date().toISOString(),
  });
});

/* ---------- Root ---------- */
app.get("/", (req, res) => {
  res.json({
    message: "CAEP SSF Transmitter (full parity)",
    issuer: ISS,
    jwks_uri: `${ISS}/.well-known/jwks.json`,
    ssf_config: `${ISS}/.well-known/ssf-configuration`,
    endpoints: [
      "/ssf/streams",
      "/ssf/streams/:id",
      "/ssf/streams/:id/delete",
      "/ssf/streams/verify",
      "/caep/send-risk-level-change",
    ],
  });
});

/* ---------- Start ---------- */
initKeys().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 CAEP transmitter running on port ${PORT}`);
    console.log(`Discovery: ${ISS}/.well-known/ssf-configuration`);
  });
});
