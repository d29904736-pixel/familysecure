require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const fs = require('fs');

const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'familysecure-super-secret-key-2026-change-this-in-production';
const PORT = process.env.PORT || 3000;

// Load or create database
if (!fs.existsSync('db.json')) {
  fs.writeFileSync('db.json', JSON.stringify({ users: [] }, null, 2));
}
let db = JSON.parse(fs.readFileSync('db.json'));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use(limiter);

// Register
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields are required' });
  if (db.users.find(u => u.email === email)) return res.status(400).json({ error: 'Email already registered' });

  const hashed = await bcrypt.hash(password, 12);
  const user = {
    id: Date.now(),
    name,
    email,
    password: hashed,
    status: 'active',
    createdAt: new Date().toISOString()
  };
  db.users.push(user);
  fs.writeFileSync('db.json', JSON.stringify(db, null, 2));
  res.json({ message: 'Registration successful' });
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.users.find(u => u.email === email);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({
    message: 'Login successful',
    token,
    user: { name: user.name, email: user.email, status: user.status }
  });
});

// Admin - Get all users
app.get('/api/admin/users', (req, res) => {
  const safeUsers = db.users.map(u => ({
    id: u.id,
    name: u.name,
    email: u.email,
    status: u.status,
    createdAt: u.createdAt
  }));
  res.json({ users: safeUsers });
});

// Update status (Emergency Surrender + Admin hold/activate)
app.post('/api/update-status', (req, res) => {
  const { email, status } = req.body;
  const user = db.users.find(u => u.email === email);
  if (!user) return res.status(404).json({ error: 'User not found' });

  user.status = status;
  fs.writeFileSync('db.json', JSON.stringify(db, null, 2));
  res.json({ message: 'Status updated successfully' });
});

app.listen(PORT, () => console.log(`✅ Secure backend running on port ${PORT}`));