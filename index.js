// index.js
import express from "express";
import jsforce from "jsforce";
import cookieSession from "cookie-session";
import crypto from "crypto";
import dotenv from "dotenv";
dotenv.config();

const {
  SALESFORCE_CLIENT_ID,
  SALESFORCE_CLIENT_SECRET,
  SALESFORCE_REDIRECT_URI,
  SALESFORCE_LOGIN_URL = "https://login.salesforce.com",
  PORT = 8080,
} = process.env;

if (!SALESFORCE_CLIENT_ID || !SALESFORCE_CLIENT_SECRET || !SALESFORCE_REDIRECT_URI) {
  console.error("❌ Missing Salesforce OAuth environment variables");
  process.exit(1);
}

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(
  cookieSession({
    name: "session",
    secret: "mcp-salesforce-cookie-secret",
    maxAge: 24 * 60 * 60 * 1000,
  })
);

// ─────────────────────────────────────
// PKCE helpers
function base64urlEncode(buf) {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest();
}

// ─────────────────────────────────────
// OAuth initiation – generates PKCE pair
app.get("/auth/salesforce", (req, res) => {
  const codeVerifier = base64urlEncode(crypto.randomBytes(32));
  const codeChallenge = base64urlEncode(sha256(codeVerifier));
  const state = base64urlEncode(crypto.randomBytes(16));

  // Stash verifier & state in the session
  req.session.codeVerifier = codeVerifier;
  req.session.state = state;

  const oauth2 = new jsforce.OAuth2({
    loginUrl: SALESFORCE_LOGIN_URL,
    clientId: SALESFORCE_CLIENT_ID,
    redirectUri: SALESFORCE_REDIRECT_URI,
  });

  const authUrl = oauth2.getAuthorizationUrl({
    response_type: "code",
    scope: "refresh_token",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    state,
  });

  res.redirect(authUrl);
});

// Proxy /authorize → Salesforce
app.get("/authorize", (req, res) => {
  const codeVerifier = base64urlEncode(crypto.randomBytes(32));
  const codeChallenge = base64urlEncode(sha256(codeVerifier));
  const state = base64urlEncode(crypto.randomBytes(16));

  req.session.codeVerifier = codeVerifier;
  req.session.state = state;

  const url = new URL(`${SALESFORCE_LOGIN_URL}/services/oauth2/authorize`);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", SALESFORCE_CLIENT_ID);
  url.searchParams.set("redirect_uri", SALESFORCE_REDIRECT_URI);
  url.searchParams.set("scope", "refresh_token offline_access full api");
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");

  res.redirect(url.toString());
});

// Proxy /token → Salesforce
app.post("/token", express.urlencoded({ extended: true }), async (req, res) => {
  const { code, redirect_uri, grant_type, client_id, client_secret, code_verifier } = req.body;

  try {
    const tokenRes = await fetch(`${SALESFORCE_LOGIN_URL}/services/oauth2/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type,
        client_id,
        client_secret,
        code,
        redirect_uri,
        code_verifier
      }),
    });

    const tokenData = await tokenRes.json();
    res.status(tokenRes.status).json(tokenData);
  } catch (err) {
    console.error("❌ Token proxy error:", err);
    res.status(500).json({ error: "Token proxy failed" });
  }
});

// ─────────────────────────────────────
// OAuth callback – validates & exchanges
app.get("/auth/callback", async (req, res) => {
  const { code, state } = req.query;

  if (!code || !state || state !== req.session.state) {
    return res.status(400).send("Invalid state or code");
  }

  try {
    const conn = new jsforce.Connection({
      oauth2: {
        loginUrl: SALESFORCE_LOGIN_URL,
        clientId: SALESFORCE_CLIENT_ID,
        clientSecret: SALESFORCE_CLIENT_SECRET,
        redirectUri: SALESFORCE_REDIRECT_URI,
      },
    });

    await conn.authorize(code, {
      code_verifier: req.session.codeVerifier,
    });

    // Save tokens in the cookie session
    req.session.accessToken = conn.accessToken;
    req.session.refreshToken = conn.refreshToken;
    req.session.instanceUrl = conn.instanceUrl;

    res.send("✅ Salesforce authorization successful! You may return to ChatGPT.");
  } catch (err) {
    console.error("❌ OAuth callback error:", err);
    res.status(500).send("OAuth callback failed");
  }
});

// ─────────────────────────────────────
// Auth-guard middleware
function ensureAuth(req, res, next) {
  if (!req.session.accessToken || !req.session.instanceUrl) {
    const baseUrl = `${req.protocol}://${req.get("host")}`;
    res.set(
      "WWW-Authenticate",
      `Bearer realm="MCP", resource_metadata_uri="${baseUrl}/.well-known/oauth-protected-resource", authorization_uri="${baseUrl}/auth/salesforce"`
    );
    return res.status(401).json({ error: "Not authenticated. Visit /auth/salesforce first." });
  }
  req.conn = new jsforce.Connection({
    accessToken: req.session.accessToken,
    refreshToken: req.session.refreshToken,
    instanceUrl: req.session.instanceUrl,
    oauth2: {
      loginUrl: SALESFORCE_LOGIN_URL,
      clientId: SALESFORCE_CLIENT_ID,
      clientSecret: SALESFORCE_CLIENT_SECRET,
    },
  });
  next();
}

// ─────────────────────────────────────
// MCP metadata (+ tools list kept unchanged)
const METADATA = {
  name: "Salesforce MCP (OAuth)",
  description: "MCP connector to query Salesforce using OAuth2",
  version: "1.0",
  auth: {
    type: "oauth2",
    authorization_type: "oauth2",
    client_url: `${SALESFORCE_LOGIN_URL}/services/oauth2/authorize`,
    token_url: `${SALESFORCE_LOGIN_URL}/services/oauth2/token`,
    scope: "refresh_token offline_access full api"
  },
  // issuer is now dynamically generated per request
  issuer: undefined,
  authorization_endpoint: `${SALESFORCE_LOGIN_URL}/services/oauth2/authorize`,
  token_endpoint: `${SALESFORCE_LOGIN_URL}/services/oauth2/token`,
  registration_endpoint: `${SALESFORCE_REDIRECT_URI.replace(/\/auth\/callback$/, "")}/register`,
  response_types_supported: ["code"],
  grant_types_supported: ["authorization_code", "refresh_token"],
  code_challenge_methods_supported: ["S256"],
  token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
  endpoints: ["/tools/list", "/call/search", "/call/fetch"]
};

app.get("/", (req, res) => {
  // Dynamically set issuer to the current request's base URL
  const baseUrl = `${req.protocol}://${req.get("host")}`;
  res.json({ ...METADATA, issuer: baseUrl });
});
app.post("/", (req, res) => {
  const baseUrl = `${req.protocol}://${req.get("host")}`;
  res.json({ ...METADATA, issuer: baseUrl });
});

// same /tools/list … /call/search … /call/fetch routes as before (omitted for brevity)

// ─────────────────────────────────────
// OAuth protected-resource metadata endpoint
app.get("/.well-known/oauth-protected-resource", (req, res) => {
  const baseUrl = `${req.protocol}://${req.get("host")}`;
  res.json({
    authorization_servers: [
      {
        issuer: baseUrl,
        authorization_endpoint: `${SALESFORCE_LOGIN_URL}/services/oauth2/authorize`
      }
    ]
  });
});

// ─────────────────────────────────────
// Dynamic Client Registration endpoint (RFC7591)
app.post("/register", express.json(), (req, res) => {
  const baseUrl = `${req.protocol}://${req.get("host")}`;
  // Return the pre‐configured client credentials with Salesforce OAuth metadata fields and RFC7591 required fields
  res.json({
    client_id: SALESFORCE_CLIENT_ID,
    client_secret: SALESFORCE_CLIENT_SECRET,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    client_secret_expires_at: 0,
    registration_client_uri: `${baseUrl}/register`,
    token_endpoint_auth_method: "client_secret_post"
  });
});

// ─────────────────────────────────────
// OAuth metadata endpoint for ChatGPT
app.get("/.well-known/oauth-authorization-server", (req, res) => {
  const baseUrl = `${req.protocol}://${req.get("host")}`;
  res.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/authorize`,
    token_endpoint: `${baseUrl}/token`,
    registration_endpoint: `${baseUrl}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
    scopes_supported: ["refresh_token", "offline_access", "api", "full"],
    response_modes_supported: ["query", "fragment"]
  });
});

// ─────────────────────────────────────
app.listen(PORT, () => console.log(`🚀 MCP server on ${PORT}`));