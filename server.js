// server.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { promisify } = require('util');

const randomBytesAsync = promisify(crypto.randomBytes);

const app = express();
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(bodyParser.json());
app.use(cookieParser());

// ENV / config
const PORT = Number(process.env.PORT || 5000);
const JWT_SECRET = process.env.JWT_SECRET || 'replace_this_with_a_strong_secret';
const ACCESS_TOKEN_EXPIRES_IN = process.env.ACCESS_TOKEN_EXPIRES_IN || '15m'; // 15 minutes
const REFRESH_TOKEN_EXPIRES_DAYS = Number(process.env.REFRESH_TOKEN_EXPIRES_DAYS || 30);
const REFRESH_COOKIE_NAME = process.env.REFRESH_COOKIE_NAME || 'refreshToken';

// Postgres pool (uses DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_DATABASE)
const pool = new Pool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : undefined
});

// Utility: parse dd/mm/yyyy into Date (UTC) or null
function parseDDMMYYYY(dobStr) {
  if (!dobStr || typeof dobStr !== 'string') return null;
  const parts = dobStr.split('/');
  if (parts.length !== 3) return null;
  let [d, m, y] = parts.map(p => p.trim());
  if (!/^\d{1,2}$/.test(d) || !/^\d{1,2}$/.test(m) || !/^\d{4}$/.test(y)) return null;
  d = Number(d); m = Number(m); y = Number(y);
  const dt = new Date(Date.UTC(y, m - 1, d, 0, 0, 0));
  if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== (m - 1) || dt.getUTCDate() !== d) return null;
  return dt;
}

// Utility: calculate age (years) accurately from UTC birth date
function calculateAgeFromDateUTC(birthDateUTC) {
  const now = new Date();
  // use UTC fields for consistent calculations
  let age = now.getUTCFullYear() - birthDateUTC.getUTCFullYear();
  const monthNow = now.getUTCMonth();
  const dayNow = now.getUTCDate();
  const monthBirth = birthDateUTC.getUTCMonth();
  const dayBirth = birthDateUTC.getUTCDate();
  if (monthNow < monthBirth || (monthNow === monthBirth && dayNow < dayBirth)) {
    age--;
  }
  return age;
}

// Ensure DB tables exist
async function ensureTables() {
  // users table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      mobile VARCHAR(20) UNIQUE NOT NULL,
      age INT NOT NULL,
      gender VARCHAR(20),
      dob DATE NOT NULL,
      password VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // refresh tokens table (hashed tokens stored)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id SERIAL PRIMARY KEY,
      user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL,
      expires_at TIMESTAMP NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // index for faster lookup by user
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);
  `);
}

// Create access token
function createAccessToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRES_IN });
}

// Create raw refresh token + its sha256 hash for DB
async function createRefreshTokenPair() {
  const raw = (await randomBytesAsync(48)).toString('hex'); // 96 hex chars
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  return { raw, hash };
}

// Store refresh token hash in DB
async function storeRefreshTokenHash(userId, tokenHash, expiresAt) {
  const q = `INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3) RETURNING id`;
  const r = await pool.query(q, [userId, tokenHash, expiresAt.toISOString()]);
  return r.rows[0];
}

// Consume (verify + delete) refresh token by raw value and userId
// returns true if consumed successfully, false otherwise
async function consumeRefreshToken(userId, providedRaw) {
  const providedHash = crypto.createHash('sha256').update(providedRaw).digest('hex');
  const q = `SELECT id, expires_at FROM refresh_tokens WHERE user_id = $1 AND token_hash = $2`;
  const r = await pool.query(q, [userId, providedHash]);
  const row = r.rows[0];
  if (!row) return false;

  if (new Date(row.expires_at) < new Date()) {
    // expired → remove
    await pool.query('DELETE FROM refresh_tokens WHERE id = $1', [row.id]);
    return false;
  }

  // valid → consume (delete for rotation)
  await pool.query('DELETE FROM refresh_tokens WHERE id = $1', [row.id]);
  return true;
}

// Middleware: check Authorization: Bearer <accessToken>
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: 'Missing Authorization header' });
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ message: 'Invalid Authorization header format' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    return next();
  } catch (err) {
    // token invalid or expired
    return res.status(401).json({ message: 'Invalid or expired access token' });
  }
}

// SIGNUP
app.post('/signup', async (req, res) => {
  try {
    const { name, mobile, age, gender, dob, password, confirmPassword } = req.body;
    if (!name || !mobile || age == null || !dob || !password || !confirmPassword) {
      return res.status(400).json({ message: 'Required fields: name, mobile, age, dob, password, confirmPassword' });
    }

    if (password !== confirmPassword) return res.status(400).json({ message: 'Passwords do not match' });

    const dobDate = parseDDMMYYYY(dob);
    if (!dobDate) return res.status(400).json({ message: 'Invalid DOB. Use dd/mm/yyyy' });

    const calculatedAge = calculateAgeFromDateUTC(dobDate);
    if (calculatedAge < 18) return res.status(400).json({ message: 'User must be at least 18 years old' });
    if (Number(age) !== calculatedAge) return res.status(400).json({ message: `Provided age (${age}) does not match DOB-derived age (${calculatedAge})` });

    const hashed = await bcrypt.hash(password, 10);

    const insert = `
      INSERT INTO users (name, mobile, age, gender, dob, password)
      VALUES ($1,$2,$3,$4,$5,$6)
      RETURNING id, name, mobile, age, gender, dob, created_at
    `;
    const values = [name, mobile, calculatedAge, gender || null, dobDate.toISOString().slice(0, 10), hashed];

    const r = await pool.query(insert, values);
    return res.status(201).json({ message: 'User registered', user: r.rows[0] });
  } catch (err) {
    if (err && err.code === '23505') {
      return res.status(400).json({ message: 'Mobile already registered' });
    }
    console.error('Signup error', err);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// LOGIN
app.post('/login', async (req, res) => {
  try {
    const { mobile, password } = req.body;
    if (!mobile || !password) return res.status(400).json({ message: 'mobile and password required' });

    const q = 'SELECT id, name, mobile, password FROM users WHERE mobile = $1';
    const r = await pool.query(q, [mobile]);
    const user = r.rows[0];
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: 'Invalid credentials' });

    const payload = { id: user.id, name: user.name, mobile: user.mobile };
    const accessToken = createAccessToken(payload);

    // create refresh token (raw + hash) and store hash
    const { raw: refreshRaw, hash: refreshHash } = await createRefreshTokenPair();
    const expiresAt = new Date(Date.now() + REFRESH_TOKEN_EXPIRES_DAYS * 24 * 60 * 60 * 1000);
    await storeRefreshTokenHash(user.id, refreshHash, expiresAt);

    // send refresh token as httpOnly cookie
    const isProd = process.env.NODE_ENV === 'production';
    res.cookie(REFRESH_COOKIE_NAME, refreshRaw, {
      httpOnly: true,
      secure: isProd,
      sameSite: 'lax',
      maxAge: REFRESH_TOKEN_EXPIRES_DAYS * 24 * 60 * 60 * 1000
    });

    return res.json({ message: 'Login successful', token: accessToken, user: payload });
  } catch (err) {
    console.error('Login error', err);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// REFRESH: exchange refresh token for new access token + rotated refresh token
app.post('/refresh', async (req, res) => {
  try {
    // refresh token raw can come from cookie or body
    const providedRaw = req.cookies?.[REFRESH_COOKIE_NAME] || req.body?.refreshToken;
    if (!providedRaw) return res.status(401).json({ message: 'Missing refresh token' });

    // attempt to identify user:
    // 1) try to decode Authorization bearer token without verify to get user id (works if client sends expired access token)
    // 2) fallback to req.body.userId (client can send), though less ideal
    let userId = null;
    const authHeader = req.headers.authorization;
    if (authHeader) {
      const parts = authHeader.split(' ');
      if (parts.length === 2 && parts[0] === 'Bearer') {
        try {
          const decoded = jwt.decode(parts[1]);
          if (decoded && decoded.id) userId = decoded.id;
        } catch (e) {
          // ignore
        }
      }
    }
    if (!userId && req.body?.userId) {
      userId = req.body.userId;
    }
    if (!userId) {
      // As last resort, try to find the refresh token across DB (less efficient). We'll hash providedRaw and search.
      const providedHash = crypto.createHash('sha256').update(providedRaw).digest('hex');
      const q = `SELECT user_id, id, expires_at FROM refresh_tokens WHERE token_hash = $1`;
      const r = await pool.query(q, [providedHash]);
      const row = r.rows[0];
      if (!row) return res.status(401).json({ message: 'Invalid refresh token' });
      if (new Date(row.expires_at) < new Date()) {
        await pool.query('DELETE FROM refresh_tokens WHERE id = $1', [row.id]);
        return res.status(401).json({ message: 'Refresh token expired' });
      }
      userId = row.user_id;
      // delete the row we found (we will rotate below)
      await pool.query('DELETE FROM refresh_tokens WHERE id = $1', [row.id]);
    } else {
      // consume token normally by userId
      const ok = await consumeRefreshToken(userId, providedRaw);
      if (!ok) return res.status(401).json({ message: 'Invalid or expired refresh token' });
    }

    // At this point userId is known and old token consumed (or removed).
    // Issue new tokens:
    const getUser = await pool.query('SELECT id, name, mobile FROM users WHERE id = $1', [userId]);
    const user = getUser.rows[0];
    if (!user) return res.status(404).json({ message: 'User not found' });

    const payload = { id: user.id, name: user.name, mobile: user.mobile };
    const accessToken = createAccessToken(payload);

    // create & store new refresh token
    const { raw: newRaw, hash: newHash } = await createRefreshTokenPair();
    const newExpiresAt = new Date(Date.now() + REFRESH_TOKEN_EXPIRES_DAYS * 24 * 60 * 60 * 1000);
    await storeRefreshTokenHash(user.id, newHash, newExpiresAt);

    // set new cookie
    const isProd = process.env.NODE_ENV === 'production';
    res.cookie(REFRESH_COOKIE_NAME, newRaw, {
      httpOnly: true,
      secure: isProd,
      sameSite: 'lax',
      maxAge: REFRESH_TOKEN_EXPIRES_DAYS * 24 * 60 * 60 * 1000
    });

    return res.json({ message: 'Token refreshed', token: accessToken });
  } catch (err) {
    console.error('Refresh error', err);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// LOGOUT: protected - delete all refresh tokens for the user and clear cookie
app.post('/logout', authMiddleware, async (req, res) => {
  try {
    await pool.query('DELETE FROM refresh_tokens WHERE user_id = $1', [req.user.id]);
    res.clearCookie(REFRESH_COOKIE_NAME);
    return res.json({ message: 'Logged out' });
  } catch (err) {
    console.error('Logout error', err);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// Protected example: /me
app.get('/me', authMiddleware, async (req, res) => {
  try {
    const q = 'SELECT id, name, mobile, age, gender, dob, created_at FROM users WHERE id = $1';
    const r = await pool.query(q, [req.user.id]);
    if (!r.rows[0]) return res.status(404).json({ message: 'User not found' });
    return res.json({ user: r.rows[0] });
  } catch (err) {
    console.error('/me error', err);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// Health check
app.get('/', (req, res) => res.send('Auth server running'));

// Startup: ensure tables then listen
ensureTables()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Auth server listening on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error('Failed to ensure DB tables', err);
    process.exit(1);
  });
