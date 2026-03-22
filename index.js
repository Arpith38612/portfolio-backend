const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors({
  origin: 'https://arpith38612.github.io',
  methods: ['GET', 'POST']
}));
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.query('CREATE TABLE IF NOT EXISTS messages (id SERIAL PRIMARY KEY, name VARCHAR(100), email VARCHAR(100), message TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');

// -- Contact Form Route --
app.post('/contact', async (req, res) => {
  const { name, email, message } = req.body;
  if (!name || !email || !message) return res.status(400).json({ error: 'All fields are required' });
  try {
    await pool.query('INSERT INTO messages (name, email, message) VALUES ($1, $2, $3)', [name, email, message]);
    res.json({ success: true, message: 'Message saved!' });
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// -- Admin Login Route --
app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === 'admin' && password === 'admin@123') {
    res.json({ success: true, token: 'arpith-admin-token' });
  } else {
    res.status(401).json({ success: false, error: 'Invalid username or password' });
  }
});

// -- Admin Messages Route (Protected) --
app.get('/admin/messages', async (req, res) => {
  const token = req.headers['authorization'];
  if (token !== 'arpith-admin-token') {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const result = await pool.query('SELECT * FROM messages ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/', (req, res) => res.json({ status: 'Backend is running!' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Server running on port ' + PORT));
