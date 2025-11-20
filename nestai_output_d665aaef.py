```javascript
// server.js
import express from 'express';
import session from 'express-session';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import csurf from 'csurf';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import { body, validationResult, sanitizeBody } from 'express-validator';
import xss from 'xss';
import https from 'https';
import fs from 'fs';
import path from 'path';

// Mock database and MFA store (replace with real DB in production)
const users = new Map(); // username -> { passwordHash, salt, roles, mfaSecret, failedAttempts, lockUntil }
const mfaTokens = new Map(); // username -> { token, expiresAt }

// Constants
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_TIME = 15 * 60 * 1000; // 15 minutes
const MFA_TOKEN_EXPIRY = 5 * 60 * 1000; // 5 minutes
const SESSION_SECRET = crypto.randomBytes(64).toString('hex');
const PORT = 8443;

// Initialize Express app
const app = express();

// Security HTTP headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'"],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
    }
  },
  referrerPolicy: { policy: 'no-referrer' },
}));

// Body parsing and cookie parsing
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

// Session management
app.use(session({
  name: 'sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true, // HTTPS only
    sameSite: 'lax',
    maxAge: 30 * 60 * 1000, // 30 minutes
  }
}));

// CSRF protection
const csrfProtection = csurf({ cookie: false });
app.use(csrfProtection);

// Rate limiter for login endpoint
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: 'Too many login attempts from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Utility: sanitize input to prevent XSS
function sanitizeInput(input) {
  return xss(input);
}

// Utility: generate random MFA token
function generateMFAToken() {
  return crypto.randomBytes(3).toString('hex'); // 6 hex chars
}

// Utility: check if account is locked
function isAccountLocked(user) {
  if (!user.lockUntil) return false;
  if (Date.now() > user.lockUntil) {
    user.lockUntil = null;
    user.failedAttempts = 0;
    return false;
  }
  return true;
}

// Middleware: enforce HTTPS
function enforceHTTPS(req, res, next) {
  if (req.secure) {
    return next();
  }
  res.status(403).send('HTTPS Required');
}

// Serve login page (GET)
app.get('/login', enforceHTTPS, (req, res) => {
  const csrfToken = req.csrfToken();
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Login</title>
<style>
  body { font-family: Arial, sans-serif; background: #f9f9f9; color: #222; }
  .container { max-width: 400px; margin: 3rem auto; padding: 2rem; background: #fff; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
  label { display: block; margin-bottom: 0.5rem; font-weight: 600; }
  input[type="text"], input[type="password"], input[type="text"].mfa { width: 100%; padding: 0.5rem; margin-bottom: 1rem; border: 1px solid #ccc; border-radius: 4px; }
  button { width: 100%; padding: 0.75rem; background: #007BFF; border: none; border-radius: 4px; color: white; font-size: 1rem; cursor: pointer; }
  button:focus, input:focus { outline: 3px solid #0056b3; }
  .error { color: #b00020; margin-bottom: 1rem; }
  .hidden { display: none; }
</style>
</head>
<body>
  <main class="container" role="main" aria-labelledby="loginTitle">
    <h1 id="loginTitle">Login</h1>
    <form id="loginForm" method="POST" action="/login" novalidate aria-describedby="formError">
      <div id="formError" class="error" aria-live="assertive"></div>
      <label for="username">Username</label>
      <input type="text" id="username" name="username" autocomplete="username" required aria-required="true" minlength="3" maxlength="50" pattern="^[a-zA-Z0-9._-]+$" />
      <label for="password">Password</label>
      <input type="password" id="password" name="password" autocomplete="current-password" required aria-required="true" minlength="8" maxlength="128" />
      <div id="mfaSection" class="hidden">
        <label for="mfaToken">Multi-Factor Authentication Code</label>
        <input type="text" id="mfaToken" name="mfaToken" inputmode="numeric" pattern="^[0-9a-fA-F]{6}$" maxlength="6" autocomplete="one-time-code" aria-required="true" />
      </div>
      <input type="hidden" name="_csrf" value="${csrfToken}" />
      <button type="submit" id="submitBtn">Login</button>
    </form>
  </main>
<script>
  (function(){
    const form = document.getElementById('loginForm');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const mfaSection = document.getElementById('mfaSection');
    const mfaInput = document.getElementById('mfaToken');
    const formError = document.getElementById('formError');
    const submitBtn = document.getElementById('submitBtn');

    // Client-side validation patterns
    const usernamePattern = /^[a-zA-Z0-9._-]{3,50}$/;
    const passwordMinLength = 8;
    const mfaPattern = /^[0-9a-fA-F]{6}$/;

    // State to track MFA step
    let mfaRequired = false;

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      formError.textContent = '';

      // Validate username
      const username = usernameInput.value.trim();
      if (!usernamePattern.test(username)) {
        formError.textContent = 'Invalid username or password.';
        usernameInput.focus();
        return;
      }

      // Validate password
      const password = passwordInput.value;
      if (password.length < passwordMinLength || password.length > 128) {
        formError.textContent = 'Invalid username or password.';
        passwordInput.focus();
        return;
      }

      // If MFA required, validate MFA token
      if (mfaRequired) {
        const mfaToken = mfaInput.value.trim();
        if (!mfaPattern.test(mfaToken)) {
          formError.textContent = 'Invalid MFA code.';
          mfaInput.focus();
          return;
        }
      }

      // Prepare payload
      const payload = {
        username,
        password,
        _csrf: form._csrf.value,
      };
      if (mfaRequired) {
        payload.mfaToken = mfaInput.value.trim();
      }

      submitBtn.disabled = true;

      try {
        const response = await fetch('/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
          },
          credentials: 'same-origin',
          body: JSON.stringify(payload),
        });

        const data = await response.json();

        if (response.ok) {
          if (data.mfaRequired) {
            mfaRequired = true;
            mfaSection.classList.remove('hidden');
            mfaInput.required = true;
            mfaInput.focus();
            formError.textContent = 'Multi-factor authentication required. Please enter your code.';
          } else if (data.success) {
            window.location.href = '/dashboard';
          } else {
            formError.textContent = 'Invalid username or password.';
          }
        } else {
          formError.textContent = data.message || 'Login failed.';
        }
      } catch {
        formError.textContent = 'An error occurred. Please try again.';
      } finally {
        submitBtn.disabled = false;
      }
    });
  })();
</script>
</body>
</html>`);
});

// POST /login endpoint
app.post('/login', enforceHTTPS, loginLimiter,
  body('username')
    .trim()
    .isLength({ min: 3, max: 50 })
    .matches(/^[a-zA-Z0-9._-]+$/)
    .escape(),
  body('password')
    .isLength({ min: 8, max: 128 }),
  body('mfaToken')
    .optional()
    .isHexadecimal()
    .isLength({ min: 6, max: 6 }),
  async (req, res) => {
    // Validate CSRF token handled by csurf middleware

    // Validate inputs
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Invalid input.' });
    }

    const username = sanitizeInput(req.body.username);
    const password = req.body.password;
    const mfaToken = req.body.mfaToken ? sanitizeInput(req.body.mfaToken) : null;

    // Lookup user
    const user = users.get(username);
    if (!user) {
      // Generic error to prevent user enumeration
      return res.status(401).json({ message: 'Invalid username or password.' });
    }

    // Check account lockout
    if (isAccountLocked(user)) {
      return res.status(429).json({ message: 'Account temporarily locked due to multiple failed login attempts. Please try again later.' });
    }

    // Verify password with bcrypt
    const passwordMatch = await bcrypt.compare(password, user.passwordHash);
    if (!passwordMatch) {
      user.failedAttempts = (user.failedAttempts || 0) + 1;
      if (user.failedAttempts >= MAX_FAILED_ATTEMPTS) {
        user.lockUntil = Date.now() + LOCK_TIME;
      }
      return res.status(401).json({ message: 'Invalid username or password.' });
    }

    // Password correct, reset failed attempts
    user.failedAttempts = 0;
    user.lockUntil = null;

    // MFA enforcement
    if (!user.mfaVerified) {
      if (!mfaToken) {
        // Generate and send MFA token (simulate sending via email/SMS)
        const token = generateMFAToken();
        mfaTokens.set(username, { token, expiresAt: Date.now() + MFA_TOKEN_EXPIRY });
        return res.status(200).json({ mfaRequired: true });
      } else {
        // Validate MFA token
        const stored = mfaTokens.get(username);
        if (!stored || stored.expiresAt < Date.now() || stored.token.toLowerCase() !== mfaToken.toLowerCase()) {
          return res.status(401).json({ message: 'Invalid MFA code.' });
        }
        mfaTokens.delete(username);
        user.mfaVerified = true;
      }
    }

    // Regenerate session ID to prevent fixation
    req.session.regenerate((err) => {
      if (err) {
        return res.status(500).json({ message: 'Internal server error.' });
      }

      // Store minimal session info with strict role validation
      req.session.user = {
        username,
        roles: Array.isArray(user.roles) ? user.roles.filter(r => typeof r === 'string') : [],
        loginTime: Date.now(),
      };

      // Set session expiration
      req.session.cookie.maxAge = 30 * 60 * 1000; // 30 minutes

      // Respond success
      return res.status(200).json({ success: true });
    });
  }
);

// Middleware: authentication and role enforcement example
function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.user || !req.session.user.roles.includes(role)) {
      return res.status(403).send('Access denied.');
    }
    next();
  };
}

// Example protected route
app.get('/dashboard', enforceHTTPS, (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  // Least privilege: only allow users with 'user' role
  if (!req.session.user.roles.includes('user')) {
    return res.status(403).send('Access denied.');
  }
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8" /><title>Dashboard</title></head>
<body>
  <h1>Welcome, ${sanitizeInput(req.session.user.username)}</h1>
  <p>Your roles: ${req.session.user.roles.map(r => sanitizeInput(r)).join(', ')}</p>
  <form method="POST" action="/logout" aria-label="Logout form">
    <input type="hidden" name="_csrf" value="${req.csrfToken()}" />
    <button type="submit">Logout</button>
  </form>
</body>
</html>`);
});

// Logout endpoint
app.post('/logout', enforceHTTPS, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('sid', { httpOnly: true, secure: true, sameSite: 'lax' });
    res.redirect('/login');
  });
});

// Initialize mock user for demonstration (username: testuser, password: StrongPass!123)
(async () => {
  const saltRounds = 12;
  const password = 'StrongPass!123';
  const passwordHash = await bcrypt.hash(password, saltRounds);
  users.set('testuser', {
    passwordHash,
    roles: ['user'],
    mfaVerified: false,
    failedAttempts: 0,
    lockUntil: null,
  });
})();

// HTTPS server setup with self-signed cert (replace with valid cert in production)
const httpsOptions = {
  key: fs.readFileSync(path.join(process.cwd(), 'certs', 'server.key')),
  cert: fs.readFileSync(path.join(process.cwd(), 'certs', 'server.crt')),
};

https.createServer(httpsOptions, app).listen(PORT, () => {
  console.log(`Secure server running on https://localhost:${PORT}`);
});
```
