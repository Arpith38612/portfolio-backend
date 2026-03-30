const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
require('dotenv').config();

const app = express();

// ✅ FIXED CORS (only change made)
app.use(cors({
  origin: [
    "http://arpphishingguard.tech",
    "https://arpphishingguard.tech",
    "https://arpith38612.github.io"
  ],
  methods: ['GET', 'POST']
}));

app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Create scans table
pool.query(`
  CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    risk_score INTEGER,
    risk_level VARCHAR(20),
    flags TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`);

// ── ANALYZE URL ──
// ── ANALYZE URL ──
app.post('/analyze', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });

  const flags = [];
  const reasons = [];
  let score = 0;

  try {
    let parsed;
    try {
      parsed = new URL(url.startsWith('http') ? url : 'http://' + url);
    } catch {
      return res.status(400).json({ error: 'Invalid URL format' });
    }

    const hostname = parsed.hostname;
    const fullUrl = url.toLowerCase();

    if (parsed.protocol === 'http:') {
      flags.push('Uses HTTP instead of HTTPS (not secure)');
      reasons.push('This URL uses HTTP instead of HTTPS, so data is not encrypted.');
      score += 20;
    }

    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipRegex.test(hostname)) {
      flags.push('Uses IP address instead of domain name');
      reasons.push('Real websites rarely use raw IP addresses. This is suspicious.');
      score += 30;
    }

    const subdomains = hostname.split('.').length - 2;
    if (subdomains > 2) {
      flags.push(`Too many subdomains (${subdomains}) — suspicious`);
      reasons.push('Too many subdomains are often used to fake real domains.');
      score += 20;
    }

    const suspiciousWords = ['login','verify','secure','update','confirm','account','banking','paypal','amazon','apple','microsoft','google','free','winner','lucky','click','signin','password','credential'];
    const foundWords = suspiciousWords.filter(w => fullUrl.includes(w));
    if (foundWords.length > 0) {
      flags.push(`Suspicious keywords found: ${foundWords.join(', ')}`);
      reasons.push('Words like login, verify, or account are commonly used in phishing.');
      score += foundWords.length * 10;
    }

    if (url.length > 75) {
      flags.push(`URL is very long (${url.length} chars)`);
      reasons.push('Long URLs are often used to hide malicious parts.');
      score += 15;
    }

    const specialCount = (url.match(/[@!%#^&*]/g) || []).length;
    if (specialCount > 2) {
      flags.push(`Too many special characters (${specialCount})`);
      reasons.push('Special characters are used to confuse users.');
      score += 15;
    }

    const lookalikes = ['paypa1','arnazon','g00gle','micros0ft','app1e','faceb00k','netfl1x'];
    lookalikes.forEach(fake => {
      if (hostname.includes(fake)) {
        flags.push(`Lookalike domain detected: "${fake}"`);
        reasons.push('This domain mimics a real brand to trick users.');
        score += 40;
      }
    });

    if (hostname.includes('-') && hostname.split('-').length > 2) {
      flags.push('Multiple hyphens in domain');
      reasons.push('Hyphens are often used in fake domains.');
      score += 15;
    }

    score = Math.min(score, 100);

    let risk_level;
    if (score >= 70) risk_level = 'HIGH';
    else if (score >= 40) risk_level = 'MEDIUM';
    else if (score >= 15) risk_level = 'LOW';
    else risk_level = 'SAFE';

    await pool.query(
      'INSERT INTO scans (url, risk_score, risk_level, flags) VALUES ($1, $2, $3, $4)',
      [url, score, risk_level, JSON.stringify(flags)]
    );

    res.json({ url, risk_score: score, risk_level, flags, reasons });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Analysis failed' });
  }
});

// ── ADMIN LOGIN ──
app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === 'admin' && password === 'admin@123') {
    res.json({ success: true, token: 'arpith-admin-token' });
  } else {
    res.status(401).json({ success: false, error: 'Invalid credentials' });
  }
});

// ── ADMIN SCANS (Protected) ──
app.get('/admin/scans', async (req, res) => {
  const token = req.headers['authorization'];
  if (token !== 'arpith-admin-token') {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const result = await pool.query('SELECT * FROM scans ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});
// ── REPORT URL ──
pool.query(`
  CREATE TABLE IF NOT EXISTS reports (
    id SERIAL PRIMARY KEY,
    url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`);

app.post('/report', async (req, res) => {
  const { url } = req.body;

  try {
    await pool.query('INSERT INTO reports (url) VALUES ($1)', [url]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Report failed' });
  }
});
app.get('/', (req, res) => res.json({ status: 'PhishGuard API is running!' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('PhishGuard server running on port ' + PORT));