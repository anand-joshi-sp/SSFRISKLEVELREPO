/**
 * CAEP SSF Transmitter (self-contained working version)
 * - Hard-coded PKCS#8 RSA key and API token
 * - Signed SETs (RS256)
 * - Bearer token for all API calls
 */

const express = require("express");
const bodyParser = require("body-parser");
const axios = require("axios");
const { SignJWT, importPKCS8, exportJWK } = require("jose");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(bodyParser.json());
const PORT = process.env.PORT || 3000;

/* ----------------------------------------------------------
   🔐 Hard-coded valid PKCS#8 private key  (for testing only)
   ---------------------------------------------------------- */
const PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDYIsOT6JDoPZSS
FlYjeDMCNYebtqspTE8OEklqdfRhCuPtgxrEKgTfx0aJflb8sYOl2oVgKcR0tXvE
FeE9DBvl7z/cMffb2OHohKhZPu9bE8fSy+NytgrKn7y33bFjqTwM6CHBGIdNsfwW
XZ3dC+R75qljMbmpaIYvznFCS4tEkoFCRlrzWRKxyCr8Bh1s1TiZW0a+LguFvZfO
0pfs4jDRq3lD97F8+d1tfEmxXv5QmRqjaLeFWeoL5vE1ai4JYvKdf8MyBd7s2RBq
PTBG8P6CBP4gE6yPT8s5A4b8T17M28FtNhFgQh3L8YIhjlEogbRMcRRm90DEHhql
DPLSZeTdAgMBAAECggEBAJ/JLLuyC4Zl5BncCBL5T7PSoz4zyKuZ39CgjdA+MOOz
SrMpRClJvVbsTRzK9GQlLrDB4m1UBtvZIlb9Mk9n8MZYoVtJjErj7Hh6nWWdGoeO
Gtwvx7nIr9qS+E4uh4PeYd1Wg5L+8wP+oPuK1ab6hfnL+LuZ7cVf8m2fSShuQFeG
+id1S3sk9TkWM3J+83ceGkKvS8v8J8qpvblX0yV2DqGi85gU3pM8VkiIx4U4wC3o
Z5DmkjFyRg6KSCM7oXvRDTJ8/LrraJbI+KRcX7eQe8+PzzKoYxXURTLHu6ssUoVz
KTGShKAg9EDLOe5MqMnvnrC1sEogVNMMvC2IB2m4FUECgYEA+ukZs+P5FQTE+gHY
mu3dKvLqv2ihb2qT4z8Yw6HYhFZKJZkB+JUncb7L3sZp7pF0d8NRtYtRIsDW/eoE
sOav6Q8j5RZiqohEkgIgb1kbvZRsSKmIUzFqkXYufhR4EG0z1akmL3T3aKlmDNdc
uv3ZOSBSZ7+NQZEsFnvsQyyp5FECgYEA2rdOc4Tnyr2uTqXePaUbnjMSQpCUdE4F
c6cx8Ft/Fz5WXwrMkSEcNj7hGeNU+/t7NjDGrPOkCkq1hEQKhbLqPf1I5VY2cXJh
Y7vM7I0/fz+L+Tk1Z03fX+Z7qM/7lFcbZ0wE3T+dM+F5gKqKYPtOdcIXKHqF8yAL
cfxI3fwrTjECgYEAxHRmviJcBV7TcthMIQzvmzjQvY9YNISIf7JMEFQYqDjD9TRV
Qp5V+Ex+q4sbom8qAYVjpuIrnAEU+Keo3zvYoAK7hxakV6fsxHoRw3zBeRbIURgN
CG4v6Zdwz6vlUNwvYkGQYo4jFzHLbR33NV2iIsc2ugfF5vRz6TVIMtDNErkCgYBM
vMJNjJZqKohDiavYF0E3T/dSGpZoqNPSqvM1TX+gIYI7I0v0xikRNaMdL+adqgxR
EZzVJRZqTXW03dA0mZKdiVStkoW8giMOfhHPrTDfDEiAQ1THYrYX0sNqxWIK6iw5
YcewDPiuwKq7L/kPKNHqT5o96q4xKBT+o2R4ZehmYQKBgHEdT3FJ9n1q0lDHOktE
fPe1osfp4+Wwr53F8uKlHjKxDIBo05W7YWSmAAt+Do1i8R3PrdeKXUQZCE5WDpp8
UeUSFv+JhE+8gqWYo6+aL7OkZIBw7aQNOv5vV7lqf0f3v9lKoO0eTd6f1eAODPTh
8a6Ok8m1FfFcpje6hZRLlZxR
-----END PRIVATE KEY-----`;

/* 🔑 Hard-coded API token */
const API_TOKEN = "Bearer test-api-token-12345";

/* Base configuration */
const ISS = "http://localhost:3000/";
const DEFAULT_AUD = "https://receiver.example.com/";
const DEFAULT_RECEIVER_URL = "https://webhook.site/<your-webhook-id>";

let signingKey, publicJwk;

/* Load key on startup */
(async () => {
  signingKey = await importPKCS8(PRIVATE_KEY_PEM, "RS256");
  publicJwk = await exportJWK(signingKey);
  publicJwk.kid = `kid-${uuidv4()}`;
  publicJwk.use = "sig";
  publicJwk.alg = "RS256";
  console.log("✅ Key loaded, kid:", publicJwk.kid);
})();

/* Helper: sign JWT payload as CAEP SET */
async function signJwt(payload) {
  const now = Math.floor(Date.now() / 1000);
  payload.iat = now;
  payload.jti = uuidv4();
  payload.iss = ISS;
  payload.aud = DEFAULT_AUD;
  return await new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", typ: "application/secevent+jwt" })
    .setIssuer(payload.iss)
    .setAudience(payload.aud)
    .setIssuedAt(payload.iat)
    .setJti(payload.jti)
    .sign(signingKey);
}

/* -------------------  JWKS  ------------------- */
app.get("/.well-known/jwks.json", (req, res) => {
  res.json({ keys: [publicJwk] });
});

/* -------------------  Create Stream  ------------------- */
app.post("/create-stream", async (req, res) => {
  const receiver_stream_url = req.body.receiver_stream_url || DEFAULT_RECEIVER_URL;
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
    "Authorization": API_TOKEN
  };
  const resp = await axios.post(receiver_stream_url, jwt, { headers, validateStatus: null });
  res.json({ sent_to: receiver_stream_url, status: resp.status, data: resp.data });
});

/* -------------------  Send Risk Change  ------------------- */
app.post("/send-risk-change", async (req, res) => {
  const p = req.body.payload || {};
  const eventType = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change";
  const setPayload = {
    iss: ISS,
    aud: DEFAULT_AUD,
    sub_id: { format: "opaque", id: "user-123" },
    events: {
      [eventType]: {
        principal: p.principal || "USER",
        current_level: (p.current_level || "LOW").toUpperCase(),
        previous_level: (p.previous_level || "HIGH").toUpperCase(),
        risk_reason: p.risk_reason || "PASSWORD_FOUND_IN_DATA_BREACH"
      }
    }
  };
  const signedSET = await signJwt(setPayload);
  const headers = {
    "Content-Type": "application/secevent+jwt",
    "Authorization": API_TOKEN
  };
  const resp = await axios.post(DEFAULT_RECEIVER_URL, signedSET, { headers, validateStatus: null });
  res.json({ sent_to: DEFAULT_RECEIVER_URL, status: resp.status, data: resp.data });
});

/* -------------------  Receive (for local testing)  ------------------- */
app.post("/receive", express.text({ type: "*/*" }), (req, res) => {
  console.log("📨 Incoming SET length:", req.body.length);
  res.json({ received: true, bytes: req.body.length });
});

/* -------------------  Root  ------------------- */
app.get("/", (req, res) => {
  res.json({
    message: "CAEP SSF transmitter - hardcoded key/token working version",
    jwks: "/.well-known/jwks.json",
    endpoints: ["/create-stream", "/send-risk-change", "/receive"]
  });
});

/* Start server */
app.listen(PORT, () => console.log(`🚀 CAEP transmitter running on port ${PORT}`));
