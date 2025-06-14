const express = require('express');
const jsforce = require('jsforce');
const session = require('express-session');

const {
  SALESFORCE_CLIENT_ID,
  SALESFORCE_CLIENT_SECRET,
  SALESFORCE_LOGIN_URL = 'https://login.salesforce.com',
  SALESFORCE_REDIRECT_URI,
  PORT = 8080
} = process.env;

if (!SALESFORCE_CLIENT_ID || !SALESFORCE_CLIENT_SECRET || !SALESFORCE_REDIRECT_URI) {
  console.error('❌ Missing Salesforce OAuth environment variables');
  process.exit(1);
}

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(session({ secret: 'mcp-salesforce-secret', resave: false, saveUninitialized: true }));

const oauth2 = new jsforce.OAuth2({
  loginUrl: SALESFORCE_LOGIN_URL,
  clientId: SALESFORCE_CLIENT_ID,
  clientSecret: SALESFORCE_CLIENT_SECRET,
  redirectUri: SALESFORCE_REDIRECT_URI
});

// 🔐 OAuth Initiation
app.get('/auth/salesforce', (req, res) => {
  const url = oauth2.getAuthorizationUrl({ scope: 'refresh_token' }); 
  res.redirect(url);
});

// 🔐 OAuth Callback
app.get('/auth/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).send('Missing code param');

  try {
    const conn = new jsforce.Connection({ oauth2 });
    await conn.authorize(code);
    req.session.accessToken = conn.accessToken;
    req.session.instanceUrl = conn.instanceUrl;
    res.send('✅ Auth success. You can now use the MCP endpoints.');
  } catch (err) {
    console.error('❌ OAuth callback error:', err.message);
    res.status(500).send('OAuth callback failed');
  }
});

// 🧠 Middleware: Require auth
function ensureAuth(req, res, next) {
  if (!req.session.accessToken || !req.session.instanceUrl) {
    return res.status(401).json({ error: 'Not authenticated. Visit /auth/salesforce first.' });
  }
  req.conn = new jsforce.Connection({
    accessToken: req.session.accessToken,
    instanceUrl: req.session.instanceUrl
  });
  next();
}

// 🌐 Shared metadata object
const metadata = {
  name: 'Salesforce MCP (OAuth)',
  description: 'MCP connector to query Salesforce using OAuth2',
  version: '1.0',
  auth: {
    type: 'oauth2',
    authorization_type: 'oauth2',
    client_url: 'https://login.salesforce.com/services/oauth2/authorize',
    token_url: 'https://login.salesforce.com/services/oauth2/token',
    scope: 'refresh_token'
  },
  endpoints: ['/tools/list', '/call/search', '/call/fetch']
};

// 🌐 Metadata
app.get('/', (_, res) => {
  console.log("📥 GET /");
  res.json(metadata);
});

app.get('/.well-known/oauth-authorization-server', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('MCP-Protocol-Version', '2024-11-05'); // Required by ChatGPT

  res.json({
    issuer: "https://mcp-salesforce-production.up.railway.app",
    authorization_endpoint: "https://login.salesforce.com/services/oauth2/authorize",
    token_endpoint: "https://login.salesforce.com/services/oauth2/token",
    registration_endpoint: "https://mcp-salesforce-production.up.railway.app/register",
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"]
  });
});

// ✅ ChatGPT compatibility
app.post('/', (_, res) => {
  console.log("📨 POST /");
  res.json(metadata);
});

// 🛠️ Tool listing
app.get('/tools/list', (_, res) => {
  res.json({
    tools: [
      {
        name: "search",
        description: "Searches Leads by name.",
        input_schema: {
          type: "object",
          properties: { query: { type: "string" } },
          required: ["query"]
        },
        output_schema: {
          type: "object",
          properties: {
            results: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  id: { type: "string" },
                  title: { type: "string" },
                  text: { type: "string" },
                  url: { type: ["string", "null"] }
                },
                required: ["id", "title", "text"]
              }
            }
          },
          required: ["results"]
        }
      },
      {
        name: "fetch",
        description: "Fetches full details for a given Lead ID.",
        input_schema: {
          type: "object",
          properties: { id: { type: "string" } },
          required: ["id"]
        },
        output_schema: {
          type: "object",
          properties: {
            id: { type: "string" },
            title: { type: "string" },
            text: { type: "string" },
            url: { type: ["string", "null"] },
            metadata: {
              type: ["object", "null"],
              additionalProperties: { type: "string" }
            }
          },
          required: ["id", "title", "text"]
        }
      }
    ]
  });
});

// 🔍 Search
app.post('/call/search', ensureAuth, async (req, res) => {
  const { query } = req.body;
  try {
    const leads = await req.conn.sobject('Lead')
      .find({ Name: { $like: `%${query}%` } }, { Id: 1, Name: 1, Company: 1, Email: 1 })
      .limit(5)
      .execute();

    res.json({
      results: leads.map(lead => ({
        id: lead.Id,
        title: lead.Name,
        text: `Company: ${lead.Company}, Email: ${lead.Email}`,
        url: null
      }))
    });
  } catch (err) {
    console.error('❌ /call/search:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// 📄 Fetch
app.post('/call/fetch', ensureAuth, async (req, res) => {
  const { id } = req.body;
  try {
    const lead = await req.conn.sobject('Lead').retrieve(id);
    res.json({
      id: lead.Id,
      title: lead.Name,
      text: `Lead: ${lead.Name}, Company: ${lead.Company}, Email: ${lead.Email}`,
      url: null,
      metadata: {
        Company: lead.Company || '',
        Email: lead.Email || '',
        Status: lead.Status || '',
        Phone: lead.Phone || ''
      }
    });
  } catch (err) {
    console.error('❌ /call/fetch error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// 🔥 Global error
app.use((err, _, res, __) => {
  console.error('🔥 Unhandled error:', err.message);
  res.status(500).json({ error: 'Unhandled server error' });
});

app.listen(PORT, () => {
  console.log(`🚀 Salesforce MCP running on port ${PORT}`);
}); 
