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
const PRIVATE_KEY_PEM = `
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCp8e/HmQdtnIrZ
JpAhgRytcDNoxFdL+bRH7dOr82MzVqJxWgS96K8on0B4kLLBcs+O4tJmytOtrLns
utOhupCTxeiBaMZ98k1lY0PRoZodv8ZIlb5pCgi0zWWvMtOPcXeFkoJbAOnW2pWW
by8RjG9Yc4ZTdw8CkXUjkh6ZwUXPVZx+oMny0RHr64BIFCJ0PudT1KP08aZpmO0F
URg0vPr8MguZXfHbDDNnyh6tIoW+MG6lCDQY81z8gDjcJwJH7oRizsrrq7mPhZVx
jM4B09G0QrhXfT/8qM0HdWw0ehn1+dXtsEHPNxgVUov+J7o6BeE0qAzJ5zfpUuxX
Ne11PHVBAgMBAAECggEAHDmU6av4xKsvCQdPOezBIuUT6XOd6zwZK+rckQWKH4bI
FcvSbxo2r1vXBlSkJhS42cz50v8xwo6c5vysKXXGVW5xxU7gr84qUt/2r9IFNaU/
7+qH14nqMNXoiITZWWh6KhEoeRC1BTEuFeCaOmRGswXh4rZ8xq0dzVa4EnQqK2A4
rUvSPflAXjU5EfIAmf6pY4q3VvLuZfy6cpXMt8U5nvlnP/0wePfuLJ0NGb3f1A5U
OMbgiBj6hXVR0nEvXAcCzXY/kLaiCXgSpkLiEkE3tqFmjFZjpdPSYtwSrjXRbXSa
ldCLG8AfDm79pDwjMRUJ+4fGmlR5aEtttTt3PQEBAQKBgQCxkK1Ub5AStxqgHHsB
VfaXFiNFrtd6g41Unm5sMxFiPH8sRHEK5rr1OJHRpf1fUIa8eMLKcm39Uo0znUUL
dN4bxpjwD+v6Q4dkBGb6ZeN0XoAEQ0LbdVbHshnxUn+jJ5q9pDp+qjQfYhF25GEl
cDlyrkG83Hc4cw+xD+bC6/8eQQKBgQDEI5D6+YpWJkFZzWy8O8NxT7AAJdPhYczW
UMCEeERibZ4yt0epwvNPxqQJ9IhCdkVGiFHu9/Awa2iPfAOPhcfbyTC1QFbANeo+
Qb+q8aO9XrD7qby2rVTDjE4MuHCDk8cXkHqkEwsqS3YfG2KprX1aajhJeMgEq6AE
Z/y0jo+JWQKBgHdSWa2yiPIVb4BmuKYxAA7eZnLzA5EvPmvEXCRXZp16a41Wbb7H
sWefPzHAmkgapx3eUFl15VuAN7EfJ12qEEq+GlL7rAo3Er49K3LG4xkYTSSTaLTI
1H4YZ5JCBUE6EotPb3FtLyzXxvYPH0gxWJrWqk95Y9ofMfnY6shqjNsBAoGABOS0
b+O4ftu6iW6+yVvDTQzH+w2vulFnD6ZkeZgZ5DGC8HSlqI7oKh+bw1Gi9T+xOfCB
QHDbByehUg8FVukbm6HeMM44CME6Re4h7F9d8cmPj7kgvGKrCxW85Wj/kO1C1ld4
drg0P+F5Ox9tKoNynSqw/vwhUpCHhIjhfMn1dMECgYAj26kTHX1Io1LoO+HrGkI/
z/k6N4wxXvWJS0cEdbepPg1ZblqxW3mLbK4E5sLeaEq1mFlUF61AhEJw5SC93RmI
8XKYcQDd6eAaO+zX0M3Yy33c7HeCKzT3DNFw5Z2phvSXyTskxgFf3RuhdrwT/GoR
60MIh3fPCgZ9uz6q+VzGEQ==
-----END PRIVATE KEY-----
`;

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
