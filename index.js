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
app.post('/analyze', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });

  const flags = [];
  let score = 0;

  try {
    // Parse URL
    let parsed;
    try {
      parsed = new URL(url.startsWith('http') ? url : 'http://' + url);
    } catch {
      return res.status(400).json({ error: 'Invalid URL format' });
    }

    const hostname = parsed.hostname;
    const fullUrl = url.toLowerCase();

    // 1. Check HTTP vs HTTPS
    if (parsed.protocol === 'http:') {
      flags.push('Uses HTTP instead of HTTPS (not secure)');
      score += 20;
    }

    // 2. IP address instead of domain
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipRegex.test(hostname)) {
      flags.push('Uses IP address instead of domain name');
      score += 30;
    }

    // 3. Too many subdomains
    const subdomains = hostname.split('.').length - 2;
    if (subdomains > 2) {
      flags.push(`Too many subdomains (${subdomains}) — suspicious`);
      score += 20;
    }

    // 4. Suspicious keywords in URL
    const suspiciousWords = ['login', 'verify', 'secure', 'update', 'confirm', 'account', 'banking', 'paypal', 'amazon', 'apple', 'microsoft', 'google', 'free', 'winner', 'lucky', 'click', 'signin', 'password', 'credential'];
    const foundWords = suspiciousWords.filter(w => fullUrl.includes(w));
    if (foundWords.length > 0) {
      flags.push(`Suspicious keywords found: ${foundWords.join(', ')}`);
      score += foundWords.length * 10;
    }

    // 5. URL length
    if (url.length > 75) {
      flags.push(`URL is very long (${url.length} chars) — phishing URLs tend to be long`);
      score += 15;
    }

    // 6. Special characters
    const specialCount = (url.match(/[@!%#^&*]/g) || []).length;
    if (specialCount > 2) {
      flags.push(`Too many special characters (${specialCount}) in URL`);
      score += 15;
    }

    // 7. Lookalike domains (common brand misspellings)
    const lookalikes = [
      ['paypa1', 'paypal'], ['arnazon', 'amazon'], ['g00gle', 'google'],
      ['micros0ft', 'microsoft'], ['app1e', 'apple'], ['faceb00k', 'facebook'],
      ['netfl1x', 'netflix'], ['instagram', 'instagram']
    ];
    lookalikes.forEach(([fake]) => {
      if (hostname.includes(fake)) {
        flags.push(`Lookalike domain detected: "${fake}" mimics a real brand`);
        score += 40;
      }
    });

    // 8. Hyphen in domain (common phishing trick)
    if (hostname.includes('-') && hostname.split('-').length > 2) {
      flags.push('Multiple hyphens in domain — common phishing pattern');
      score += 15;
    }

    // Cap score at 100
    score = Math.min(score, 100);

    // Determine risk level
    let risk_level;
    if (score >= 70) risk_level = 'HIGH';
    else if (score >= 40) risk_level = 'MEDIUM';
    else if (score >= 15) risk_level = 'LOW';
    else risk_level = 'SAFE';

    // Save to database
    await pool.query(
      'INSERT INTO scans (url, risk_score, risk_level, flags) VALUES ($1, $2, $3, $4)',
      [url, score, risk_level, JSON.stringify(flags)]
    );

    res.json({ url, risk_score: score, risk_level, flags });

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

app.get('/', (req, res) => res.json({ status: 'PhishGuard API is running!' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('PhishGuard server running on port ' + PORT));