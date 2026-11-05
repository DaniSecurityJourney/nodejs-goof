# AI Code Assistant — Secure Generation & Project Instruction File

## Purpose
Provide concise, enforceable guidance and code patterns for the AI Code Assistant tool so generated code avoids known security issues (headers, secrets, CSRF, cookies, XSS, HTTPS, hardcoded credentials, DoS via expensive operations, NoSQL injection, open redirect). These rules must be followed by the assistant when authoring or modifying repository code.

## High-level policies (apply to all generated code)
- Favor secure-by-default settings and explicit, conservative options for security-sensitive APIs.
- Never generate or commit secrets, passwords, API keys, or credentials in source code. Use environment variables, secret managers, or configuration files not checked into VCS (see "Secrets & Credentials").
- Always validate and sanitize untrusted input (including query params, headers, body, cookies) using whitelists and schema validation.
- Apply safe defaults for web frameworks (disable identifying headers, enable secure cookies, CSRF protection, CSP/HSTS).
- Add appropriate automated checks (linting, static analysis, secrets scanning, dependency scanning, unit tests) and document required CI gates in PR descriptions.
- Provide short security rationale/notes in generated PRs for non-obvious decisions (e.g., relaxed CSP for legacy content).

## Secrets & Credentials
- Never emit literal secrets in code. Use:
  - process.env for Node.js runtime configuration,
  - a secrets management service (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager),
  - .env only for local dev and include a .env.example in repo (no real secrets).
- Example pattern (Node.js):
```javascript
// config.js
module.exports = {
  SESSION_SECRET: process.env.SESSION_SECRET || (() => { throw new Error('SESSION_SECRET not set'); })(),
  DB_URI: process.env.DB_URI || 'mongodb://localhost:27017/app-dev',
};
```
- Add pre-commit and CI secret scanning (e.g., git-secrets, trufflehog, detect-secrets) to block accidental commits.

## Express / HTTP server hardening
- Disable server identification header:
```javascript
// app.js
const express = require('express');
const helmet = require('helmet');
const app = express();

app.disable('x-powered-by'); // prevents X-Powered-By header
app.use(helmet()); // sensible defaults (CSP/HSTS configured below)
```
- Enforce HTTPS and HSTS in production:
```javascript
// enforce-https.js
function enforceHTTPS(req, res, next) {
  // If behind proxy set: app.set('trust proxy', 1)
  if (!req.secure && process.env.NODE_ENV === 'production') {
    return res.redirect(301, `https://${req.headers.host}${req.originalUrl}`);
  }
  next();
}
module.exports = enforceHTTPS;
```
- Add HSTS via helmet (production only):
```javascript
app.use(helmet.hsts({ maxAge: 63072000, includeSubDomains: true, preload: true }));
```

## Cookies
- Use secure cookie attributes for session and sensitive cookies:
```javascript
// example session setup
const session = require('express-session');
app.use(session({
  name: 'sid',
  secret: config.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // true only in HTTPS production
    sameSite: 'lax' // or 'strict' where compatible
  }
}));
```
- When generating cookie code, require explicit secure flag based on environment and document if `secure` is relaxed for local/dev.

## CSRF Protection
- Use csurf for form/API protections where applicable. Generate code to include csurf middleware and expose CSRF tokens safely:
```javascript
const csurf = require('csurf');
const cookieParser = require('cookie-parser');

app.use(cookieParser());
app.use(csurf({ cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax' } }));

// Example route to expose token to a template or client
app.get('/form', (req, res) => {
  res.render('form', { csrfToken: req.csrfToken() });
});
```
- For JSON APIs used by single-page apps, use double-submit cookie pattern or appropriate CSRF protection on state-changing endpoints.

## XSS & Content Security Policy
- Sanitize and escape output. Prefer templating engines that auto-escape values (e.g., Pug, EJS with escaping enabled).
- Validate input (see validation section) and encode outputs.
- Use Content Security Policy (CSP) to mitigate XSS:
```javascript
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"], // add nonces or hashes for allowed inline scripts
    styleSrc: ["'self'"],
    imgSrc: ["'self'","data:"],
    connectSrc: ["'self'"],
  }
}));
```
- Avoid or document any use of unsafe-inline or wildcard ('*'). If inline scripts are required, prefer strict-dynamic/nonces or hashes.

## Input Validation & NoSQL Injection Prevention
- Always validate and sanitize request input using schema validators (Joi, express-validator, Yup).
- For MongoDB/NoSQL backends: disallow operator injection and keys that begin with "$" or contain ".". Example sanitizer:
```javascript
function sanitizeForMongo(obj) {
  if (typeof obj !== 'object' || obj === null) return obj;
  if (Array.isArray(obj)) return obj.map(sanitizeForMongo);
  const cleaned = {};
  for (const [k, v] of Object.entries(obj)) {
    if (k.startsWith('$') || k.includes('.')) continue; // drop dangerous keys
    cleaned[k] = sanitizeForMongo(v);
  }
  return cleaned;
}

// usage in route
app.post('/search', (req, res, next) => {
  const input = sanitizeForMongo(req.body);
  // validate schema then use safely with ORM/driver
});
```
- Prefer parameterized ORM/ODM methods (e.g., Mongoose query building or parameterized queries) and avoid constructing query objects directly from raw input.
- Example with Mongoose:
```javascript
const { body, validationResult } = require('express-validator');

app.post('/users/search', 
  body('username').isAlphanumeric().isLength({max:50}), 
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const username = req.body.username;
    User.find({ username }).limit(50).exec().then(...);
});
```

## Open Redirect Prevention
- Never redirect to arbitrary user-supplied URLs. Implement allowlist checking or require relative paths only.
```javascript
const allowedHosts = new Set(['example.com', 'app.example.com']);
function safeRedirect(req, res, target, fallback = '/') {
  try {
    const url = new URL(target, `https://${req.headers.host}`);
    if (url.origin === `https://${req.headers.host}` || allowedHosts.has(url.hostname)) {
      return res.redirect(302, url.toString());
    }
  } catch (e) {
    // treat as relative path
    if (target && target.startsWith('/')) return res.redirect(302, target);
  }
  return res.redirect(302, fallback);
}
```
- For generated code, default to using relative redirect targets or require an explicit allowlist entry.

## Rate Limiting & Throttling
- Apply rate limits to public and expensive endpoints (search, auth, resource-intensive tasks).
```javascript
const rateLimit = require('express-rate-limit');

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // adjust per endpoint
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', apiLimiter);

// Stronger limits for expensive routes:
app.use('/api/expensive', rateLimit({ windowMs: 60*1000, max: 10 }));
```
- For long-running operations, use job queues (Bull, RabbitMQ) with concurrency limits and authentication/authorization checks.

## Passwords & Authentication
- Do not hardcode passwords. When generating sample code, use environment variables or placeholder tokens in .env.example.
- Store passwords using strong, adaptive hashing (bcrypt, argon2) with appropriate cost factors; never use custom hashing.
- Example using bcrypt:
```javascript
const bcrypt = require('bcrypt');
const SALT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);
async function hashPassword(plain) {
  return await bcrypt.hash(plain, SALT_ROUNDS);
}
```

## Dependency & Transport Security
- Prefer TLS for all external communication. For dev environments, document when plain HTTP is acceptable and ensure production defaults to TLS.
- Validate third-party endpoints and use certificate validation. Do not disable TLS verification in generated client code.
- Keep dependencies up to date and include dependency scanning in CI (npm audit, Snyk, GitHub Dependabot).

## Testing, CI, and Pre-merge Requirements
- Generated changes must include or update relevant unit/integration tests for:
  - Input validation,
  - Authentication/authorization,
  - CSRF token behavior (if applicable),
  - Cookie attributes,
  - Rate limiting boundaries,
  - NoSQL injection sanitizers (tests for operator injection attempts),
  - Open redirect prevention.
- CI gates required for PRs:
  - Linting and static analysis,
  - Secrets scanning,
  - Dependency vulnerability scan,
  - Unit test coverage threshold (project standard),
  - Security-focused static scan (as already in use).
- Include a short security checklist in PR description stating which mitigations were added.

## Code Generation Rules for the AI Assistant
- Do not generate hardcoded secrets/credentials, literal private keys, or test passwords in any file. If testing requires credentials, emit placeholders and reference .env.example.
- When generating Express code:
  - include app.disable('x-powered-by');
  - configure helmet and CSP,
  - use csurf for state-changing routes,
  - set secure, httpOnly, sameSite cookie flags depending on NODE_ENV,
  - include HSTS for production,
  - include input validation and sanitizer helpers before DB operations,
  - include rate limiting middleware on routes that can be abused.
- For database access code, always prefer parameterized/ORM methods and validate/sanitize inputs. Do not build queries via string concatenation or direct merge of raw client input.
- For redirects, use safeRedirect helper and never call res.redirect(req.body.next) without validation.
- For any security-sensitive choice where backward compatibility is impacted, include a short comment explaining the trade-off and a migration note.

## Example Security Helpers (include in repo as small utilities)
- sanitizeForMongo (see NoSQL section).
- safeRedirect (see Open Redirect section).
- enforceHTTPS middleware.
- csrf middleware and cookie config example.
- centralized config module that loads secrets from env and throws if required secrets are missing.

## Documentation & Developer Guidance
- Add or update README SECURITY section:
  - How to set secrets (local vs production),
  - How to run local dev safely (cookie secure false only in local with clear instructions),
  - How to run scans locally,
  - Where to find CSP and CSRF configuration.
- Require that generated code includes comments pointing to relevant docs for any non-obvious security behavior.

## Auditing & Continuous Improvement
- Failed security scans or new vulnerability discoveries must be added to this instruction file as updates.
- Encourage periodic review of these rules and update snippets for newer best practices (e.g., CSP improvements, csurf updates, cookie SameSite changes).

## Minimal Example: Secure Express App Skeleton
```javascript
// server.js (skeleton)
const express = require('express');
const helmet = require('helmet');
const csurf = require('csurf');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const config = require('./config');

const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.set('trust proxy', 1); // if behind proxy/load balancer

// HTTPS enforcement (production)
app.use(require('./enforce-https'));

// parsing
app.use(express.json());
app.use(cookieParser());

// sessions (secure cookie settings)
app.use(session({
  secret: config.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax' }
}));

// CSRF protection
app.use(csurf({ cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production' } }));

// Rate limiting
app.use('/api/', rateLimit({ windowMs: 15*60*1000, max: 100 }));

// Example safe route using input validation + NoSQL sanitizer
const { body, validationResult } = require('express-validator');
const { sanitizeForMongo } = require('./utils');

app.post('/users/search',
  body('username').isAlphanumeric().isLength({ max: 50 }),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const safeInput = sanitizeForMongo({ username: req.body.username });
    // use parameterized query with ORM/ODM
    // User.find(safeInput).then(...)
    res.json({ ok: true });
});

app.listen(process.env.PORT || 3000);
```

## Enforcement & Review Expectations for Generated PRs
- Generated PRs must:
  - Reference this instruction file and list which rules were implemented,
  - Include unit tests for security-critical code paths,
  - Pass CI security scanners and not introduce new hardcoded secrets,
  - Include short notes where defaults were intentionally relaxed (with rationale).

--- 
End of instruction file.