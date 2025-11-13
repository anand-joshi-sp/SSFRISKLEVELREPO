/**
 * Spec-compliant CAEP / SSF Transmitter (transmitter-only)
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

/* --------------------------- CONFIG --------------------------- */
const PORT = process.env.PORT || 3000;
const ISS = (process.env.ISS || "https://ssfrisklevelrepo.onrender.com").replace(/\/$/, "");
const DEFAULT_AUD = process.env.AUD || "https://ssfrisklevelrepo.onrender.com";

/* ------------------- PRIVATE KEY ------------------- */
const KEY_PATH = path.join(__dirname, "private_key_pkcs8.pem");
let PRIVATE_KEY_PEM;
try {
  PRIVATE_KEY_PEM = fs.readFileSync(KEY_PATH, "utf8");
  console.log("🔑 Loaded private key from", KEY_PATH);
} catch (err) {
  console.error("Missing private_key_pkcs8.pem");
  process.exit(1);
}

/* ------------------- INIT KEYS ------------------- */
let signingKey;
let publicJwk;

async function initKeys() {
  try {
    signingKey = await importPKCS8(PRIVATE_KEY_PEM, "RS256");
    publicJwk = await exportJWK(signingKey);
    publicJwk.kid = publicJwk.kid || `kid-${uuidv4()}`;
    publicJwk.use = "sig";
    publicJwk.alg = "RS256";
    console.log("✅ Signing key ready, kid =", publicJwk.kid);
  } catch (err) {
    console.error("Key import failed:", err.message);
    process.exit(1);
  }
}

/* ------------------- SIGN SET ------------------- */
async function signSET(payload) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT(payload)
    .setProtectedHeader({
      alg: "RS256",
      typ: "secevent+jwt",
      kid: publicJwk.kid,
    })
    .setIssuedAt(now)
    .setIssuer(ISS)
    .setAudience(payload.aud || DEFAULT_AUD)
    .setJti(uuidv4())
    .sign(signingKey);
}

/* ------------------- VERIFY INCOMING SET ------------------- */
async function verifyIncomingSET(token) {
  const header = await decodeProtectedHeader(token);
  const kid = header.kid;

  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("invalid_jwt_format");

  const payloadJson = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  const jwks_uri = payloadJson.jwks_uri;
  if (!jwks_uri) throw new Error("jwks_uri_missing");

  const jwksResp = await axios.get(jwks_uri);
  const jwk = jwksResp.data.keys.find((k) => k.kid === kid) || jwksResp.data.keys[0];

  if (!jwk) throw new Error("jwk_not_found");

  const key = await importJWK(jwk, jwk.alg || "RS256");

  const verified = await jwtVerify(token, key, {
    issuer: payloadJson.iss,
    audience: payloadJson.aud,
  });

  return { payload: verified.payload, header };
}

/* ------------------- STREAM STORE ------------------- */
const streams = {};

/* ------------------- WELL-KNOWN ------------------- */
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
  });
});

/* ------------------- AUTH MIDDLEWARE ------------------- */
app.use("/ssf", (req, res, next) => {
  if (req.headers.authorization !== "Bearer token123") {
    return res.status(401).json({ error: "unauthorized" });
  }
  next();
});

/* ------------------- CREATE STREAM ------------------- */
app.post("/ssf/streams", (req, res) => {
  try {
    const body = req.body || {};

    if (!body.aud) body.aud = ISS;
    if (!body.jwks_uri) body.jwks_uri = `${ISS}/.well-known/jwks.json`;

    let delivery = body.delivery || {};
    const endpoint =
      delivery.endpoint ||
      delivery.endpoint_url ||
      delivery.URL ||
      delivery.url;

    const method = delivery.method;

    if (!endpoint || !method) {
      return res.status(400).json({
        error: "invalid_delivery",
        message: "delivery.method and delivery.endpoint required",
      });
    }

    const required = ["iss", "aud", "jwks_uri", "events_requested"];
    const missing = required.filter((f) => !(f in body));
    if (missing.length) {
      return res.status(400).json({ error: `missing_fields: ${missing.join(", ")}` });
    }

    const id = uuidv4();
    const now = new Date().toISOString();

    const stream = {
      stream_id: id,
      iss: body.iss,
      aud: body.aud,
      jwks_uri: body.jwks_uri,
      delivery: {
        method,
        endpoint,
        authorization_header: delivery.authorization_header || "Bearer token123",
      },
      events_requested: body.events_requested,
      events_accepted: body.events_requested,
      events_delivered: body.events_requested,
      description: body.description || null,
      status: "enabled",
      created_at: now,
      updated_at: now,
    };

    streams[id] = stream;

    res.status(201).json(stream);
  } catch (err) {
    res.status(500).json({ error: "internal_error", message: err.message });
  }
});

/* ------------------- GET STREAMS ------------------- */
app.get("/ssf/streams", (req, res) => {
  res.json(Object.values(streams));
});

/* ------------------- GET STREAM BY ID ------------------- */
app.get("/ssf/streams/:id", (req, res) => {
  const s = streams[req.params.id];
  if (!s) return res.status(404).json({ error: "stream_not_found" });
  res.json(s);
});

/* ------------------- UPDATE STREAM ------------------- */
app.post("/ssf/streams/:id", (req, res) => {
  const s = streams[req.params.id];
  if (!s) return res.status(404).json({ error: "stream_not_found" });

  const updates = req.body || {};

  if (updates.delivery) {
    s.delivery = { ...s.delivery, ...updates.delivery };
  }
  if (updates.events_requested) {
    s.events_requested = updates.events_requested;
    s.events_accepted = updates.events_requested;
    s.events_delivered = updates.events_requested;
  }
  if ("description" in updates) s.description = updates.description;
  if ("status" in updates) s.status = updates.status;

  s.updated_at = new Date().toISOString();
  res.json(s);
});

/* ------------------- DELETE STREAM ------------------- */
app.post("/ssf/streams/:id/delete", (req, res) => {
  if (!streams[req.params.id]) {
    return res.status(404).json({ error: "stream_not_found" });
  }
  delete streams[req.params.id];
  res.status(204).send();
});

/* ------------------- VERIFY STREAM ------------------- */
app.post("/ssf/streams/verify", async (req, res) => {
  const { stream_id } = req.body || {};
  const s = streams[stream_id];
  if (!s) return res.status(404).json({ error: "stream_not_found" });

  const eventType = "https://schemas.openid.net/secevent/ssf/event-type/verification";

  const verifyPayload = {
    iss: ISS,
    aud: s.delivery.endpoint,
    sub_id: { format: "opaque", id: stream_id },
    events: { [eventType]: {} }
  };

  const signed = await signSET(verifyPayload);

  const headers = {
    "Content-Type": "application/secevent+jwt",
    Authorization: s.delivery.authorization_header
  };

  axios.post(s.delivery.endpoint, signed, { headers })
    .then(() => console.warn(`🔐 Verification SET sent → ${s.delivery.endpoint}`))
    .catch(err => console.warn(`❌ Verification send failed: ${err.message}`));

  res.status(202).json({ message: "verification_sent", stream_id });
});


/* ------------------- STREAM STATUS ------------------- */
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
    timestamp: new Date().toISOString()
  });
});


/* ============================================================
   SHARED METRICS (for all CAEP event send endpoints)
   ============================================================ */
if (!global.metrics) {
  global.metrics = {
    risk: { sent: 0, success: 0, failed: 0 },
    status: { sent: 0, success: 0, failed: 0 },
    device: { sent: 0, success: 0, failed: 0 }
  };
}

function logEvent(type, endpoint, resp) {
  const m = global.metrics[type];
  m.sent++;

  const ok = resp.status >= 200 && resp.status < 300;
  if (ok) m.success++;
  else m.failed++;

  console.warn(
    `${ok ? "✅" : "❌"} [${type.toUpperCase()} EVENT DELIVERY]\n` +
    `→ Target: ${endpoint}\n` +
    `→ HTTP: ${resp.status}\n` +
    `→ Body: ${JSON.stringify(resp.data)}\n` +
    `→ Stats: sent=${m.sent}, success=${m.success}, failed=${m.failed}`
  );
}

/* ============================================================
   CAEP EVENT: RISK LEVEL CHANGE
   ============================================================ */
app.post("/caep/send-risk-level-change", async (req, res) => {
  try {
    const { stream_id, receiver_url, payload } = req.body || {};

    if (!payload || !payload.principal || !payload.current_level) {
      return res.status(400).json({ error: "payload.principal_and_current_level_required" });
    }

    let target, authHeader;

    if (stream_id) {
      const s = streams[stream_id];
      if (!s) return res.status(404).json({ error: "stream_not_found" });

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

    const signed = await signSET(setPayload);

    const headers = { "Content-Type": "application/secevent+jwt" };
    if (authHeader) headers["Authorization"] = authHeader;

    const resp = await axios
      .post(target, signed, { headers, validateStatus: () => true })
      .catch(e => e.response || { status: 500, data: String(e) });

    logEvent("risk", target, resp);

    res.status(200).json({
      message: "risk_level_change_sent",
      http_status: resp.status,
      receiver_response: resp.data || null,
    });
  } catch (err) {
    console.error("risk-level-change error:", err.message);
    res.status(500).json({ error: "internal_error", message: err.message });
  }
});


/* ============================================================
   CAEP EVENT: STATUS CHANGE
   ============================================================ */
app.post("/caep/send-status-change", async (req, res) => {
  try {
    const { stream_id, payload } = req.body || {};

    if (!stream_id) return res.status(400).json({ error: "stream_id_required" });

    const s = streams[stream_id];
    if (!s) return res.status(404).json({ error: "stream_not_found" });

    const eventType = "https://schemas.openid.net/secevent/caep/event-type/status-change";

    const setPayload = {
      iss: ISS,
      aud: payload.aud || DEFAULT_AUD,
      sub_id: payload.sub_id || { format: "opaque", id: "unknown" },
      events: {
        [eventType]: {
          principal: payload.principal,
          current_status: payload.current_status,
          ...(payload.previous_status ? { previous_status: payload.previous_status } : {}),
          ...(payload.reason ? { reason: payload.reason } : {}),
          ...(payload.event_timestamp ? { event_timestamp: payload.event_timestamp } : {})
        }
      }
    };

    const signed = await signSET(setPayload);

    const headers = {
      "Content-Type": "application/secevent+jwt",
      Authorization: s.delivery.authorization_header,
    };

    const resp = await axios
      .post(s.delivery.endpoint, signed, { headers, validateStatus: () => true })
      .catch(e => e.response || { status: 500, data: String(e) });

    logEvent("status", s.delivery.endpoint, resp);

    res.status(200).json({
      message: "status_change_sent",
      http_status: resp.status,
      receiver_response: resp.data || null
    });
  } catch (err) {
    console.error("status-change error:", err.message);
    res.status(500).json({ error: "internal_error", message: err.message });
  }
});
/* ============================================================
   CAEP EVENT: DEVICE COMPLIANCE CHANGE
   ============================================================ */
app.post("/caep/send-device-compliance-change", async (req, res) => {
  try {
    const { stream_id, payload } = req.body || {};

    if (!stream_id)
      return res.status(400).json({ error: "stream_id_required" });

    const s = streams[stream_id];
    if (!s) return res.status(404).json({ error: "stream_not_found" });

    const eventType =
      "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change";

    const setPayload = {
      iss: ISS,
      aud: payload.aud || DEFAULT_AUD,
      sub_id: payload.sub_id, // user supplies complex/email/opaque
      events: {
        [eventType]: {
          current_status: payload.current_status,
          ...(payload.previous_status
            ? { previous_status: payload.previous_status }
            : {}),
          ...(payload.event_timestamp
            ? { event_timestamp: payload.event_timestamp }
            : {}),
        },
      },
    };

    const signed = await signSET(setPayload);

    const headers = {
      "Content-Type": "application/secevent+jwt",
      Authorization: s.delivery.authorization_header,
    };

    const resp = await axios
      .post(s.delivery.endpoint, signed, {
        headers,
        validateStatus: () => true,
        timeout: 20000,
      })
      .catch((e) => e.response || { status: 500, data: String(e) });

    logEvent("device", s.delivery.endpoint, resp);

    res.status(200).json({
      message: "device_compliance_change_sent",
      http_status: resp.status,
      receiver_response: resp.data || null,
    });
  } catch (err) {
    console.error("send-device-compliance-change error:", err.message);
    res.status(500).json({ error: "internal_error", message: err.message });
  }
});
/* Root */
app.get("/", (req, res) => {
  res.json({
    message: "Spec-compliant SSF/CAEP Transmitter",
    issuer: ISS,
    discovery: `${ISS}/.well-known/ssf-configuration`,
    jwks: `${ISS}/.well-known/jwks.json`,
    metrics: global.metrics
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
