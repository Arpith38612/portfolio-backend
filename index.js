const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Create table if it doesn't exist
pool.query(`
  CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(100),
    message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`);

// Contact form route
app.post('/contact', async (req, res) => {
  const { name, email, message } = req.body;

  if (!name || !email || !message) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    await pool.query(
      'INSERT INTO messages (name, email, message) VALUES ($1, $2, $3)',
      [name, email, message]
    );
    res.json({ success: true, message: 'Message saved!' });
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Test route
app.get('/', (req, res) => {
  res.json({ status: 'Backend is running!' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
```

---

## Step 3 — Create a file called `.env`:
```
DATABASE_URL=your_database_url_here
```

(We'll fill this in after setting up Render database)

---

## Step 4 — Create a file called `.gitignore`:
```
node_modules
.env