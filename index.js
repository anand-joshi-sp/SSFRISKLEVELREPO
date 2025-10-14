/**
 * Spec-compliant CAEP / SSF Transmitter (transmitter-only)
 *
 * - Reads PKCS#8 private key from ./private_key_pkcs8.pem (required)
 * - POST /ssf/streams accepts a signed SET (application/secevent+jwt) from a Receiver to register a stream
 *   -> verifies signature using jwks_uri present in the SET payload
 * - GET /ssf/streams/:id  -> 200 with stream config
 * - PATCH /ssf/streams/:id -> 200 with updated config
 * - DELETE /ssf/streams?stream_id=... -> 204 No Content
 * - POST /ssf/verify -> accepts JSON { stream_id, state? } -> responds 204 and sends verification SET to stream.delivery.endpoint
 * - POST /caep/send-risk-level-change -> send CAEP SET to a registered stream (requires stream_id or receiver_url)
 * - /.well-known/ssf-configuration and /.well-known/jwks.json
 *
 * Environment:
 *   PORT (default 3000)
 *   ISS (issuer URL, required for production; default http://localhost:3000)
 *
 * Usage:
 *   1) Generate key: openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private_key_pkcs8.pem
 *   2) npm install
 *   3) node index.js
 */

const fs = require("fs");
const path = require("path");
const express = require("express");
const bodyParser = require("body-parser");
const axios = require("axios");
const {
  SignJWT,
  importPKCS8,
  exportJWK,
  decodeProtectedHeader,
  jwtVerify,
  importJWK,
} = require("jose");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(bodyParser.json({ limit: "1mb" }));

/* ---------- Configuration ---------- */
const PORT = process.env.PORT || 3000;
const ISS = (process.env.ISS || `http://localhost:${PORT}`).replace(/\/$/, "");
const DEFAULT_AUD = process.env.AUD || "https://receiver.example.com/";

/* ---------- Load private key from file (PKCS#8) ---------- */
const KEY_PATH = path.join(__dirname, "private_key_pkcs8.pem");
let PRIVATE_KEY_PEM;
try {
  PRIVATE_KEY_PEM = fs.readFileSync(KEY_PATH, "utf8");
  console.log("🔑 Loaded private key from", KEY_PATH);
} catch (err) {
  console.error("Missing or unreadable private_key_pkcs8.pem. Generate with OpenSSL and place in project root.");
  process.exit(1);
}

/* ---------- Initialize JOSE signing key and publish JWK ---------- */
let signingKey;
let publicJwk;
async function initKeys() {
  try {
    signingKey = await importPKCS8(PRIVATE_KEY_PEM, "RS256");
    publicJwk = await exportJWK(signingKey);
    publicJwk.kid = publicJwk.kid || `kid-${uuidv4()}`;
    publicJwk.use = "sig";
    publicJwk.alg = publicJwk.alg || "RS256";
    console.log("✅ Signing key ready, kid =", publicJwk.kid);
  } catch (err) {
    console.error("[FATAL] Unable to import PRIVATE_KEY_PEM:", err && err.message ? err.message : err);
    process.exit(1);
  }
}

/* ---------- Helpers ---------- */

/** Sign a payload as an application/secevent+jwt SET */
async function signSET(payload) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", typ: "application/secevent+jwt" })
    .setIssuedAt(now)
    .setIssuer(ISS)
    .setAudience(payload.aud || DEFAULT_AUD)
    .setJti(uuidv4())
    .sign(signingKey);
}

/** Verify incoming SET (signed JWT) using jwks_uri found in payload */
async function verifyIncomingSET(token) {
  // get header to find kid/alg
  const header = await decodeProtectedHeader(token);
  const kid = header.kid;
  // decode payload without verifying to read jwks_uri
  // jwtVerify requires a key; we'll fetch jwks_uri from an unverified decode
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("invalid_jwt_format");
  const payloadJson = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  const jwks_uri = payloadJson.jwks_uri;
  if (!jwks_uri) throw new Error("jwks_uri_missing_in_payload");

  // fetch jwks
  const jwksResp = await axios.get(jwks_uri, { timeout: 10000 });
  if (!jwksResp || !jwksResp.data || !Array.isArray(jwksResp.data.keys)) {
    throw new Error("jwks_invalid_or_unreachable");
  }
  const jwk = jwksResp.data.keys.find((k) => k.kid === kid) || jwksResp.data.keys[0];
  if (!jwk) throw new Error("matching_jwk_not_found");

  // import jwk and verify
  const key = await importJWK(jwk, jwk.alg || "RS256");
  const verified = await jwtVerify(token, key, { issuer: payloadJson.iss, audience: payloadJson.aud });
  // verified.payload is the payload
  return { payload: verified.payload, header: header };
}

/* ---------- In-memory store (streams) ---------- */
/*
  stream object shape (spec-like):
  {
    stream_id,
    iss,           // optional - who registered
    jwks_uri,      // receiver jwks uri (if provided in registration)
    delivery: { method, endpoint, authorization_header, endpoint_url? },
    events_requested: [],
    events_accepted: [],
    description: null,
    status: "enabled" | "disabled",
    created_at, updated_at
  }
*/
const streams = {};

/* ---------- WELL-KNOWN endpoints ---------- */
app.get("/.well-known/jwks.json", (req, res) => res.json({ keys: [publicJwk] }));

app.get("/.well-known/ssf-configuration", (req, res) => {
  res.json({
    issuer: ISS,
    jwks_uri: `${ISS}/.well-known/jwks.json`,
    registration_endpoint: `${ISS}/ssf/streams`,
    status_endpoint: `${ISS}/ssf/status`,
    delivery_methods_supported: ["push", "poll"],
    events_supported: ["https://schemas.openid.net/secevent/caep/event-type/risk-level-change"],
    authorization_types_supported: ["bearer"],
    signed_set_alg_values_supported: ["RS256"],
    version: "1.0",
  });
});

/* ---------- SPEC-COMPLIANT Endpoints ---------- */

/**
 * CREATE STREAM (Receiver registers with Transmitter)
 * Expects Content-Type: application/secevent+jwt (signed SET)
 * Verifies SET using jwks_uri included in payload.
 * Responds 201 Created with stream config JSON on success.
 */
app.post("/ssf/streams", async (req, res) => {
  try {
    // raw body may be a JWT string. Ensure we support text body for this route.
    // express.json already parsed JSON; but we expect a string token in req.body if JSON-literal. Also support raw text if client sends raw JWT.
    let token;
    if (typeof req.body === "string") {
      token = req.body;
    } else if (req.body && req.body.token && typeof req.body.token === "string") {
      token = req.body.token;
    } else {
      // if content-type is application/secevent+jwt but parser didn't handle it, try raw buffer
      token = "";
    }
    if (!token) {
      // try reading raw buffer fallback (some clients may send raw)
      return res.status(400).json({ error: "must_post_signed_set_jwt" });
    }

    // Verify incoming SET using receiver's jwks_uri
    let verified;
    try {
      verified = await verifyIncomingSET(token);
    } catch (err) {
      return res.status(400).json({ error: "invalid_set", detail: err && err.message ? err.message : String(err) });
    }

    const payload = verified.payload;

    // Build stream object from payload per spec fields (delivery, events_requested, jwks_uri, iss)
    const stream_id = uuidv4();
    const delivery = payload.delivery || null;
    const events_requested = Array.isArray(payload.events_requested) ? payload.events_requested : [];
    const jwks_uri = payload.jwks_uri || null;
    const description = payload.description || null;
    const status = "enabled";

    const stream = {
      stream_id,
      iss: payload.iss || null,
      jwks_uri,
      delivery,
      events_requested,
      events_accepted: events_requested.slice(),
      description,
      status,
      created_at: new Date().toISOString(),
    };

    streams[stream_id] = stream;

    // Respond 201 with stream config (per spec)
    res.status(201).json(stream);
  } catch (err) {
    console.error("create stream error:", err);
    res.status(500).json({ error: "internal_error" });
  }
});

/**
 * GET stream list or single stream
 * - GET /ssf/streams -> list
 * - GET /ssf/streams/:id -> single
 * Both return 200 OK and JSON.
 */
app.get("/ssf/streams", (req, res) => {
  const list = Object.values(streams);
  res.status(200).json(list);
});

app.get("/ssf/streams/:id", (req, res) => {
  const id = req.params.id;
  const s = streams[id];
  if (!s) return res.status(404).json({ error: "stream_not_found" });
  res.status(200).json(s);
});

/**
 * PATCH /ssf/streams/:id
 * Accepts JSON with allowed updatable fields: delivery, events_requested, description, status
 * Returns 200 with full updated stream JSON
 */
app.patch("/ssf/streams/:id", (req, res) => {
  const id = req.params.id;
  const s = streams[id];
  if (!s) return res.status(404).json({ error: "stream_not_found" });

  const updates = req.body || {};
  if (updates.delivery) s.delivery = Object.assign({}, s.delivery || {}, updates.delivery);
  if (updates.events_requested) {
    if (!Array.isArray(updates.events_requested)) return res.status(400).json({ error: "invalid_events_requested" });
    s.events_requested = updates.events_requested;
    s.events_accepted = updates.events_requested.slice();
  }
  if ("description" in updates) s.description = updates.description;
  if ("status" in updates) s.status = updates.status;
  s.updated_at = new Date().toISOString();

  res.status(200).json(s);
});

/**
 * DELETE /ssf/streams?stream_id=...
 * Spec requires deletion using query param. Return 204 No Content on success.
 */
app.delete("/ssf/streams", (req, res) => {
  const sid = req.query.stream_id;
  if (!sid) return res.status(400).json({ error: "stream_id_required" });
  if (!streams[sid]) return res.status(404).json({ error: "stream_not_found" });
  delete streams[sid];
  return res.status(204).send();
});

/**
 * POST /ssf/verify
 * Accepts JSON body { stream_id, state? }
 * Responds 204 No Content and sends a Verification SET to the stream.delivery.endpoint (best-effort)
 */
app.post("/ssf/verify", async (req, res) => {
  const { stream_id, state } = req.body || {};
  if (!stream_id) return res.status(400).json({ error: "stream_id_required" });
  const s = streams[stream_id];
  if (!s) return res.status(404).json({ error: "stream_not_found" });

  const verificationPayload = {
    jti: uuidv4(),
    iss: ISS,
    aud: s.delivery && s.delivery.endpoint ? s.delivery.endpoint : DEFAULT_AUD,
    iat: Math.floor(Date.now() / 1000),
    sub_id: { format: "opaque", id: stream_id },
    events: {
      "https://schemas.openid.net/secevent/ssf/event-type/verification": state ? { state } : {},
    },
  };

  // sign and send asynchronously, do not block responding 204 per spec example
  signSET(verificationPayload)
    .then((signed) => {
      const headers = { "Content-Type": "application/secevent+jwt" };
      if (s.delivery && s.delivery.authorization_header) headers["Authorization"] = s.delivery.authorization_header;
      axios.post(s.delivery.endpoint, signed, { headers }).catch((e) => {
        console.warn("verification send failed:", e && e.message ? e.message : e);
      });
    })
    .catch((err) => console.warn("signing verification SET failed:", err && err.message ? err.message : err));

  return res.status(204).send();
});

/* ---------- /ssf/status (health & stream summary) ---------- */
app.get("/ssf/status", (req, res) => {
  const summary = Object.values(streams).map((s) => ({
    stream_id: s.stream_id,
    endpoint: s.delivery && s.delivery.endpoint,
    status: s.status,
  }));
  res.status(200).json({ status: "active", stream_count: summary.length, streams: summary, time: new Date().toISOString() });
});

/* ---------- CAEP event send endpoint ---------- */
/**
 * POST /caep/send-risk-level-change
 * Body: { stream_id?, receiver_url?, payload: { principal, current_level, previous_level?, risk_reason?, event_timestamp?, sub_id? } }
 * Must provide either stream_id (preferred) or receiver_url. No global/default fallbacks are used.
 */
app.post("/caep/send-risk-level-change", async (req, res) => {
  try {
    const { stream_id, receiver_url, payload } = req.body || {};
    if (!payload || !payload.principal || !payload.current_level) {
      return res.status(400).json({ error: "payload.principal_and_current_level_required" });
    }

    let target;
    let authHeader;
    if (stream_id) {
      const s = streams[stream_id];
      if (!s) return res.status(404).json({ error: "stream_not_found" });
      if (!s.delivery || !s.delivery.endpoint) return res.status(400).json({ error: "stream_has_no_delivery_endpoint" });
      target = s.delivery.endpoint;
      authHeader = s.delivery.authorization_header;
    } else if (receiver_url) {
      target = receiver_url;
      authHeader = req.body.authorization_header || null;
    } else {
      return res.status(400).json({ error: "stream_id_or_receiver_url_required" });
    }

    const eventType = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change";
    const setPayload = {
      iss: ISS,
      aud: payload.aud || DEFAULT_AUD,
      sub_id: payload.sub_id || { format: "opaque", id: "unknown" },
      events: {
        [eventType]: {
          principal: payload.principal,
          current_level: String(payload.current_level).toUpperCase(),
          ...(payload.previous_level ? { previous_level: String(payload.previous_level).toUpperCase() } : {}),
          ...(payload.risk_reason ? { risk_reason: payload.risk_reason } : {}),
          ...(payload.event_timestamp ? { event_timestamp: payload.event_timestamp } : {}),
        },
      },
    };

    // sign
    const signed = await signSET(setPayload);

    // prepare headers; use stream-specific auth if present
    const headers = { "Content-Type": "application/secevent+jwt" };
    if (authHeader) headers["Authorization"] = authHeader;

    // send and return receiver response
    const resp = await axios.post(target, signed, { headers, validateStatus: () => true, timeout: 20000 }).catch((e) => e.response || { status: 500, data: String(e) });
    return res.status(200).json({ message: "sent", http_status: resp.status, receiver_response: resp.data || null });
  } catch (err) {
    console.error("send-risk-level-change error:", err && err.message ? err.message : err);
    return res.status(500).json({ error: "internal_error" });
  }
});

/* Root */
app.get("/", (req, res) => {
  res.json({
    message: "Spec-compliant SSF/CAEP Transmitter",
    issuer: ISS,
    discovery: `${ISS}/.well-known/ssf-configuration`,
    jwks: `${ISS}/.well-known/jwks.json`,
  });
});

/* ---------- Start server ---------- */
initKeys()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`🚀 Transmitter listening on ${PORT}`);
      console.log(`Discovery: ${ISS}/.well-known/ssf-configuration`);
    });
  })
  .catch((err) => {
    console.error("Key init failed:", err);
    process.exit(1);
  });
