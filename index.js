/**
 * Spec-compliant CAEP / SSF Transmitter (Configuration / Status / Verify)
 *
 * Implements SSF Event Stream Management endpoints per OpenID SSF 1.0:
 *  - POST /ssf/streams   (create)  -> 201 Created with JSON stream config
 *  - GET  /ssf/streams   (list or ?stream_id=) -> 200 OK
 *  - GET  /ssf/streams/:id -> 200 OK
 *  - PATCH /ssf/streams/:id -> 200 OK (updated config)
 *  - DELETE /ssf/streams  (query ?stream_id=...) -> 204 No Content
 *  - POST /ssf/verify -> 204 No Content
 *  - GET/POST /ssf/status -> status read/update (per spec examples)
 *
 * Also exposes:
 *  - /.well-known/ssf-configuration
 *  - /.well-known/jwks.json
 *  - POST /caep/send-risk-level-change (signed SET push)
 *
 * See OpenID SSF spec: create stream behavior, status codes, verification examples.
 * (Spec refs included when returning responses.)
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

/* ---------- Config ---------- */
const PORT = process.env.PORT || 3000;
const API_TOKEN = process.env.API_TOKEN || "Bearer test-api-token-12345";
const ISS = (process.env.ISS || "https://ssfrisklevelrepo.onrender.com").replace(/\/$/, "");
const DEFAULT_AUD = process.env.AUD || "https://receiver.example.com/";
const DEFAULT_RECEIVER_URL =
  process.env.DEFAULT_RECEIVER_URL || "https://webhook.site/<your-webhook-id>";

/* ---------- Load private key from file (avoid inline PEM issues) ---------- */
let PRIVATE_KEY_PEM;
try {
  PRIVATE_KEY_PEM = fs.readFileSync(path.join(__dirname, "private_key_pkcs8.pem"), "utf8");
  console.log("🔑 Loaded private key from disk");
} catch (err) {
  console.error("Missing private_key_pkcs8.pem. Generate with OpenSSL (genpkey).");
  process.exit(1);
}

/* ---------- Setup JOSE signing key and JWKS ---------- */
let signingKey, publicJwk;
async function initKeys() {
  try {
    signingKey = await importPKCS8(PRIVATE_KEY_PEM, "RS256");
    publicJwk = await exportJWK(signingKey);
    publicJwk.kid = publicJwk.kid || `kid-${uuidv4()}`;
    publicJwk.use = "sig";
    publicJwk.alg = publicJwk.alg || "RS256";
    console.log("✅ Signing key loaded; jwk.kid =", publicJwk.kid);
  } catch (err) {
    console.error("[FATAL] Failed to import PRIVATE_KEY_PEM:", err && err.message ? err.message : err);
    process.exit(1);
  }
}

/* ---------- Helper to sign SET/SSF payloads ---------- */
async function signSET(payload, typ = "application/secevent+jwt") {
  const now = Math.floor(Date.now() / 1000);
  return await new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", typ })
    .setIssuedAt(now)
    .setIssuer(ISS)
    .setAudience(payload.aud || DEFAULT_AUD)
    .setJti(uuidv4())
    .sign(signingKey);
}

/* ---------- In-memory stores (for demo / test) ---------- */
/* stream object fields (spec): stream_id (transmitter-supplied), delivery, events_requested, events_accepted, status, created_at */
const streams = {};          // keyed by stream_id
const receiverIndex = {};    // map receiver identifier => array of stream_ids (simple mapping for multi/one-stream logic)

/* ---------- WELL-KNOWN endpoints (discovery) ---------- */
app.get("/.well-known/jwks.json", (req, res) => res.json({ keys: [publicJwk] }));

app.get("/.well-known/ssf-configuration", (req, res) => {
  res.json({
    issuer: ISS,
    jwks_uri: `${ISS}/.well-known/jwks.json`,
    registration_endpoint: `${ISS}/ssf/streams`, // config endpoint (we also accept /ssf/stream for examples)
    status_endpoint: `${ISS}/ssf/status`,
    delivery_methods_supported: ["push", "poll"],
    events_supported: [
      "https://schemas.openid.net/secevent/caep/event-type/risk-level-change",
    ],
    authorization_types_supported: ["bearer"],
    signed_set_alg_values_supported: ["RS256"],
    version: "1.0",
  });
});

/* ------------------------
   SPEC-COMPLIANT API HANDLERS
   Reference: OpenID SSF 1.0 (create/GET/PATCH/DELETE/verify/status examples & status codes).
   See: create stream (201), read (200), update (200), delete (204), verify (204), error codes table.
   :contentReference[oaicite:5]{index=5}
   ------------------------ */

/* HELPER: require Authorization Bearer token (Receiver must authenticate). */
function requireAuth(req, res) {
  const auth = req.headers.authorization || "";
  if (!auth || !auth.toLowerCase().startsWith("bearer ")) {
    res.status(401).json({ error: "missing_or_invalid_authorization" });
    return false;
  }
  // Note: in production you'd validate token scope/audience etc. For tests, accept any Bearer.
  return true;
}

/**
 * CREATE STREAM
 * - Path: POST /ssf/streams  (we also accept POST /ssf/stream for spec example compatibility)
 * - Request body: JSON with optional keys: delivery, events_requested, description (per spec)
 * - Response: 201 Created + JSON stream configuration
 *
 * Spec: "An Event Receiver creates a stream by making an HTTP POST request to the Configuration Endpoint.
 * On receiving a valid request the Event Transmitter responds with a '201 Created' response containing
 * a JSON representation of the stream's configuration in the body." :contentReference[oaicite:6]{index=6}
 */
async function handleCreateStream(req, res) {
  if (!requireAuth(req, res)) return;

  // Validate payload
  const body = req.body || {};
  // Per spec events_requested MAY be provided; delivery MAY be provided. Validate minimal structure.
  const eventsRequested = Array.isArray(body.events_requested) ? body.events_requested : [];
  const delivery = body.delivery || null; // if null, transmitter MUST assume poll (per spec)
  const description = body.description || null;

  // Basic validation: delivery.method if present must be a supported method
  if (delivery && delivery.method && !["urn:ietf:rfc:8935", "urn:ietf:rfc:8936", "push", "poll"].includes(delivery.method)) {
    // Spec: If the Transmitter does not support the delivery method, it MAY respond with 400 Bad Request.
    return res.status(400).json({ error: "unsupported_delivery_method" });
  }

  // Decide whether multiple streams per receiver allowed:
  // For simplicity, allow multiple streams by default. If you want single-stream-per-receiver enforce here and return 409.
  // Spec: If the Transmitter does not allow multiple streams with the same Receiver, MUST return 409. :contentReference[oaicite:7]{index=7}
  const receiverId = (req.headers["x-receiver-id"] || req.headers["x-client-id"] || null); // optional hint
  if (receiverId && receiverIndex[receiverId] && receiverIndex[receiverId].length > 0) {
    // Example: if you want to reject multiple streams uncomment below and return 409:
    // return res.status(409).json({ error: "multiple_streams_not_allowed" });
  }

  // Create stream object (Transmitter MUST generate unique stream_id)
  const stream_id = uuidv4();
  const stream = {
    stream_id,
    iss: ISS,
    jwks_uri: `${ISS}/.well-known/jwks.json`,
    delivery: delivery || { method: "urn:ietf:rfc:8936", endpoint_url: `${ISS}/poll/${stream_id}` }, // poll default per spec L90
    events_requested: eventsRequested,
    events_accepted: eventsRequested, // transmitter can accept subset; for now echo requested
    description,
    status: "enabled",
    created_at: new Date().toISOString(),
  };

  streams[stream_id] = stream;
  if (receiverId) {
    receiverIndex[receiverId] = receiverIndex[receiverId] || [];
    receiverIndex[receiverId].push(stream_id);
  }

  // Respond 201 Created with JSON stream configuration (spec requirement). :contentReference[oaicite:8]{index=8}
  res.status(201).json(stream);
}

/* Accept both /ssf/streams and example /ssf/stream for interoperability */
app.post("/ssf/streams", handleCreateStream);
app.post("/ssf/stream", handleCreateStream);

/**
 * READ stream(s)
 * - GET /ssf/streams?stream_id=...  OR GET /ssf/streams  (list)
 * - GET /ssf/streams/:id
 *
 * Spec: On valid request respond with 200 OK and JSON representation. If stream_id missing, return list (possibly empty). :contentReference[oaicite:9]{index=9}
 */
app.get("/ssf/streams", (req, res) => {
  if (!requireAuth(req, res)) return;
  const sid = req.query.stream_id;
  if (sid) {
    const s = streams[sid];
    if (!s) return res.status(404).json({ error: "stream_not_found" });
    return res.status(200).json(s);
  }
  // Return list of stream configurations available to this Receiver (as array)
  const list = Object.values(streams);
  return res.status(200).json(list);
});
app.get("/ssf/streams/:id", (req, res) => {
  if (!requireAuth(req, res)) return;
  const s = streams[req.params.id];
  if (!s) return res.status(404).json({ error: "stream_not_found" });
  return res.status(200).json(s);
});

/**
 * PATCH /ssf/streams/:id
 * - Update properties (PATCH per spec)
 * - Respond 200 OK with the full updated stream configuration on success.
 * - Error codes: 400, 401, 403, 404 (per spec) :contentReference[oaicite:10]{index=10}
 */
app.patch("/ssf/streams/:id", (req, res) => {
  if (!requireAuth(req, res)) return;
  const id = req.params.id;
  const s = streams[id];
  if (!s) return res.status(404).json({ error: "stream_not_found" });

  const updates = req.body || {};
  // Only allow certain updatable fields (spec: receiver-supplied fields) — events_requested and delivery may be updatable.
  if (updates.events_requested) {
    if (!Array.isArray(updates.events_requested)) return res.status(400).json({ error: "invalid_events_requested" });
    s.events_requested = updates.events_requested;
  }
  if (updates.delivery) {
    s.delivery = Object.assign({}, s.delivery, updates.delivery);
  }
  if (typeof updates.description !== "undefined") s.description = updates.description;

  s.updated_at = new Date().toISOString();
  return res.status(200).json(s);
});

/**
 * DELETE /ssf/streams  (query param stream_id=...)  OR DELETE /ssf/stream?stream_id=...
 * - Spec requires deletion by query param stream_id and on success respond with 204 No Content. :contentReference[oaicite:11]{index=11}
 */
async function handleDeleteStream(req, res) {
  if (!requireAuth(req, res)) return;
  const sid = req.query.stream_id;
  if (!sid) return res.status(400).json({ error: "stream_id_required" });
  const s = streams[sid];
  if (!s) return res.status(404).json({ error: "stream_not_found" });

  delete streams[sid];
  // remove from receiverIndex if present
  for (const k of Object.keys(receiverIndex)) {
    receiverIndex[k] = (receiverIndex[k] || []).filter(x => x !== sid);
  }
  // Spec: respond 204 No Content on success. :contentReference[oaicite:12]{index=12}
  res.status(204).send();
}
app.delete("/ssf/streams", handleDeleteStream);
app.delete("/ssf/stream", handleDeleteStream);

/**
 * Verification Endpoint
 * - POST /ssf/verify  with JSON body { stream_id: "...", state: "..." }
 * - On success respond 204 No Content (spec example). The Transmitter SHOULD send the Verification Event to the Receiver. :contentReference[oaicite:13]{index=13}
 */
app.post("/ssf/verify", (req, res) => {
  if (!requireAuth(req, res)) return;
  const body = req.body || {};
  const sid = body.stream_id;
  if (!sid) return res.status(400).json({ error: "stream_id_required" });

  const s = streams[sid];
  if (!s) return res.status(404).json({ error: "stream_not_found" });

  // prepare Verification SET (per spec) and send to stream delivery endpoint asynchronously
  const verificationEvent = {
    jti: uuidv4(),
    iss: ISS,
    aud: s.delivery && s.delivery.endpoint_url ? s.delivery.endpoint_url : DEFAULT_AUD,
    iat: Math.floor(Date.now() / 1000),
    sub_id: { format: "opaque", id: sid },
    events: {
      "https://schemas.openid.net/secevent/ssf/event-type/verification": {
        ...(body.state ? { state: body.state } : {})
      }
    }
  };

  // sign and POST asynchronously; spec: Transmitter may do this asynchronously and respond 204
  signSET(verificationEvent).then(signed => {
    const headers = { "Content-Type": "application/secevent+jwt", Authorization: API_TOKEN };
    // best-effort send; do not block responding 204
    axios.post(s.delivery.endpoint_url || DEFAULT_RECEIVER_URL, signed, { headers }).catch(e => {
      console.warn("verification send failed (logged):", e && e.message ? e.message : e);
    });
  }).catch(err => console.warn("signSET failed:", err && err.message ? err.message : err));

  // Respond 204 No Content per spec (successful request accepted). :contentReference[oaicite:14]{index=14}
  res.status(204).send();
});

/**
 * Status endpoints
 * - GET /ssf/status?stream_id=...  -> 200 with status object (spec example)
 * - POST /ssf/status  -> update status, respond 200 with updated status JSON (per spec)
 */
app.get("/ssf/status", (req, res) => {
  if (!requireAuth(req, res)) return;
  const sid = req.query.stream_id;
  if (!sid) {
    // return a summary for all streams visible
    const list = Object.values(streams).map(s => ({ stream_id: s.stream_id, endpoint: s.delivery && s.delivery.endpoint_url, status: s.status }));
    return res.status(200).json({ status: "active", stream_count: list.length, streams: list });
  }
  const s = streams[sid];
  if (!s) return res.status(404).json({ error: "stream_not_found" });
  return res.status(200).json({ stream_id: s.stream_id, status: s.status });
});

app.post("/ssf/status", (req, res) => {
  if (!requireAuth(req, res)) return;
  const b = req.body || {};
  if (!b.stream_id || !b.status) return res.status(400).json({ error: "stream_id_and_status_required" });
  const s = streams[b.stream_id];
  if (!s) return res.status(404).json({ error: "stream_not_found" });
  s.status = b.status;
  if (b.reason) s.status_reason = b.reason;
  s.status_updated_at = new Date().toISOString();
  return res.status(200).json({ stream_id: s.stream_id, status: s.status });
});

/* ------------------------
   CAEP event send (unchanged) — transmitter can also send events to receiver endpoints
   Note: events must be signed SETs (we sign them here); keep Authorization header if required
   ------------------------ */
app.post("/caep/send-risk-level-change", async (req, res) => {
  const p = req.body.payload || {};
  if (!p.principal || !p.current_level) return res.status(400).json({ error: "principal_and_current_level_required" });

  const target = req.body.receiver_url || DEFAULT_RECEIVER_URL;
  const eventType = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change";
  const setPayload = {
    iss: ISS,
    aud: p.aud || DEFAULT_AUD,
    sub_id: p.sub_id || { format: "opaque", id: "unknown" },
    events: {
      [eventType]: {
        principal: p.principal,
        current_level: String(p.current_level).toUpperCase(),
        ...(p.previous_level ? { previous_level: String(p.previous_level).toUpperCase() } : {}),
        ...(p.risk_reason ? { risk_reason: p.risk_reason } : {}),
        ...(p.event_timestamp ? { event_timestamp: p.event_timestamp } : {})
      }
    }
  };

  try {
    const signed = await signSET(setPayload);
    const headers = { "Content-Type": "application/secevent+jwt", Authorization: API_TOKEN };
    const resp = await axios.post(target, signed, { headers, validateStatus: () => true });
    return res.status(200).json({ message: "sent", http_status: resp.status, receiver_response: resp.data || null });
  } catch (err) {
    console.error("send-risk-level-change error:", err && err.message ? err.message : err);
    return res.status(500).json({ error: "internal_error" });
  }
});

/* Root & start */
app.get("/", (req, res) => {
  res.json({
    message: "SSF Transmitter (spec-compliant endpoints)",
    discovery: `${ISS}/.well-known/ssf-configuration`,
    jwks: `${ISS}/.well-known/jwks.json`,
  });
});

initKeys().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Spec-compliant CAEP/SSF transmitter listening on ${PORT}`);
    console.log(`Discovery: ${ISS}/.well-known/ssf-configuration`);
  });
});
