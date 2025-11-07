/**
 * Spec-compliant CAEP / SSF Transmitter (transmitter-only)
 *
 * - Reads PKCS#8 private key from ./private_key_pkcs8.pem (required)
 * - POST /ssf/streams accepts either:
 *      - Raw JSON registration (CAEP/SSF style)
 *      - Signed SET (secevent+jwt) from a Receiver, verifies signature using jwks_uri
 * - GET /ssf/streams/:id  -> 200 with stream config
 * - PATCH /ssf/streams/:id -> 200 with updated config
 * - DELETE /ssf/streams/:id/delete -> 204 No Content
 * - POST /ssf/streams/verify -> accepts JSON { stream_id } -> responds 202 and sends verification SET to delivery endpoint
 * - POST /caep/send-risk-level-change -> send CAEP SET (requires stream_id or receiver_url)
 * - POST /caep/send-device-compliance-change -> send device-compliance-change SET
 * - /.well-known/ssf-configuration and /.well-known/jwks.json
 */

const fs = require("fs");
const path = require("path");
const express = require("express");
const bodyParser = require("body-parser");
const axios = require("axios");
const { SignJWT, importPKCS8, exportJWK, decodeProtectedHeader, jwtVerify, importJWK } = require("jose");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(bodyParser.json({ limit: "2mb" }));

/* ---------------- Configuration ---------------- */
const PORT = process.env.PORT || 3000;
const ISS = (process.env.ISS || "https://ssfrisklevelrepo.onrender.com").replace(/\/$/, "");
const DEFAULT_AUD = process.env.AUD || ISS;
const BEARER_TOKEN = "Bearer token123";

/* ---------------- Load private key ---------------- */
const KEY_PATH = path.join(__dirname, "private_key_pkcs8.pem");
let PRIVATE_KEY_PEM = fs.readFileSync(KEY_PATH, "utf8");

/* ---------------- Init signing key ---------------- */
let signingKey, publicJwk;
async function initKeys() {
  signingKey = await importPKCS8(PRIVATE_KEY_PEM, "RS256");
  publicJwk = await exportJWK(signingKey);
  publicJwk.kid = publicJwk.kid || `kid-${uuidv4()}`;
  publicJwk.use = "sig";
  publicJwk.alg = "RS256";
  console.log("✅ Key ready, kid =", publicJwk.kid);
}

/* ---------------- Sign helper ---------------- */
async function signSET(payload) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", typ: "secevent+jwt", kid: publicJwk.kid })
    .setIssuedAt(now)
    .setIssuer(ISS)
    .setAudience(payload.aud || DEFAULT_AUD)
    .setJti(uuidv4())
    .sign(signingKey);
}

/* ---------------- Verify helper ---------------- */
async function verifyIncomingSET(token) {
  const header = decodeProtectedHeader(token);
  const kid = header.kid;
  const [_, payloadB64] = token.split(".");
  const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
  const jwks_uri = payload.jwks_uri;
  if (!jwks_uri) throw new Error("jwks_uri_missing_in_payload");

  const { data } = await axios.get(jwks_uri, { timeout: 10000 });
  if (!data.keys || !Array.isArray(data.keys)) throw new Error("invalid_jwks_response");
  const jwk = data.keys.find(k => k.kid === kid) || data.keys[0];
  const key = await importJWK(jwk, jwk.alg || "RS256");
  const verified = await jwtVerify(token, key, { issuer: payload.iss, audience: payload.aud });
  return verified.payload;
}

/* ---------------- In-memory stream store ---------------- */
const streams = {};

/* ---------------- Well-known endpoints ---------------- */
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
    authorization_schemes: [{ spec_urn: "urn:ietf:rfc:6749" }],
    events_supported: [
      "https://schemas.openid.net/secevent/caep/event-type/risk-level-change",
      "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"
    ]
  });
});

/* ---------------- Authorization ---------------- */
app.use("/ssf", (req, res, next) => {
  if (req.headers.authorization !== BEARER_TOKEN)
    return res.status(401).json({ error: "unauthorized" });
  next();
});

/* ---------------- Stream Management ---------------- */
app.post("/ssf/streams", async (req, res) => {
  try {
    const isJWT = req.is("secevent+jwt") || (typeof req.body === "string" && req.body.split(".").length === 3);
    let payload;

    if (isJWT) {
      // Receiver registered via signed SET
      const token = typeof req.body === "string" ? req.body : req.body.raw;
      payload = await verifyIncomingSET(token);
    } else {
      // Raw JSON registration
      payload = req.body;
    }

    const delivery = payload.delivery || {};
    const endpoint = delivery.endpoint || delivery.endpoint_url;
    const method = delivery.method?.includes("push")
      ? "urn:ietf:rfc:8935"
      : delivery.method?.includes("poll")
      ? "urn:ietf:rfc:8936"
      : delivery.method;

    if (!endpoint || !method)
      return res.status(400).json({ error: "invalid_delivery" });

    const id = uuidv4();
    const now = new Date().toISOString();
    const stream = {
      stream_id: id,
      iss: payload.iss,
      aud: payload.aud || ISS,
      jwks_uri: payload.jwks_uri || `${ISS}/.well-known/jwks.json`,
      delivery: { method, endpoint, authorization_header: delivery.authorization_header || BEARER_TOKEN },
      events_requested: payload.events_requested || [],
      events_accepted: payload.events_requested || [],
      events_delivered: payload.events_requested || [],
      description: payload.description || null,
      status: "enabled",
      created_at: now,
      updated_at: now
    };
    streams[id] = stream;
    res.status(201).json(stream);
  } catch (e) {
    console.error("Stream registration error:", e.message);
    res.status(400).json({ error: "invalid_set", message: e.message });
  }
});

app.get("/ssf/streams", (_, res) => res.json(Object.values(streams)));
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
app.post("/ssf/streams/verify", async (req, res) => {
  const s = streams[req.body.stream_id];
  if (!s) return res.status(404).json({ error: "stream_not_found" });
  const payload = {
    iss: ISS,
    aud: s.delivery.endpoint,
    sub_id: { format: "opaque", id: s.stream_id },
    events: { "https://schemas.openid.net/secevent/ssf/event-type/verification": {} }
  };
  const signed = await signSET(payload);
  axios.post(s.delivery.endpoint, signed, { headers: { "Content-Type": "secevent+jwt" } }).catch(() => {});
  res.status(202).json({ message: "verification_sent", stream_id: s.stream_id });
});
app.get("/ssf/status", (_, res) =>
  res.json({
    status: "active",
    streams: Object.values(streams),
    time: new Date().toISOString()
  })
);

/* ---------------- CAEP Events ---------------- */
async function sendSET(eventType, payload, s) {
  const setPayload = {
    iss: ISS,
    aud: payload.aud || DEFAULT_AUD,
    sub_id: payload.sub_id || { format: "opaque", id: payload.principal || "unknown" },
    events: { [eventType]: payload }
  };
  const signed = await signSET(setPayload);
  return axios.post(s.delivery.endpoint, signed, {
    headers: { "Content-Type": "secevent+jwt", Authorization: s.delivery.authorization_header },
    validateStatus: () => true,
    timeout: 20000
  });
}

app.post("/caep/send-risk-level-change", async (req, res) => {
  const { stream_id, payload } = req.body;
  const s = streams[stream_id];
  if (!s) return res.status(404).json({ error: "stream_not_found" });
  const event = {
    principal: payload.principal,
    current_level: String(payload.current_level).toUpperCase(),
    previous_level: payload.previous_level,
    risk_reason: payload.risk_reason,
    event_timestamp: payload.event_timestamp || Math.floor(Date.now() / 1000)
  };
  const r = await sendSET("https://schemas.openid.net/secevent/caep/event-type/risk-level-change", event, s);
  res.json({ message: "sent", http_status: r.status });
});

app.post("/caep/send-device-compliance-change", async (req, res) => {
  const { stream_id, payload } = req.body;
  const s = streams[stream_id];
  if (!s) return res.status(404).json({ error: "stream_not_found" });
  const event = {
    principal: payload.principal,
    device: payload.device,
    compliance_state: payload.compliance_state,
    previous_state: payload.previous_state,
    reason: payload.reason,
    event_timestamp: payload.event_timestamp || Math.floor(Date.now() / 1000)
  };
  const r = await sendSET("https://schemas.openid.net/secevent/caep/event-type/device-compliance-change", event, s);
  res.json({ message: "sent", http_status: r.status });
});

/* ---------------- Root ---------------- */
app.get("/", (req, res) => {
  res.json({
    message: "Fully CAEP/SSF Compliant Transmitter",
    issuer: ISS,
    jwks: `${ISS}/.well-known/jwks.json`,
    discovery: `${ISS}/.well-known/ssf-configuration`
  });
});

/* ---------------- Start ---------------- */
initKeys().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Transmitter running on port ${PORT}`);
    console.log(`Discovery: ${ISS}/.well-known/ssf-configuration`);
  });
});
