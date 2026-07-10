require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-to-a-very-long-random-string-1234567890';

app.use(helmet());
app.use(cors());
app.use(bodyParser.json({ limit: '10kb' }));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use('/api/', limiter);

let users = [];
const dbFile = path.join(__dirname, 'db.json');
if (fs.existsSync(dbFile)) {
  const data = JSON.parse(fs.readFileSync(dbFile, 'utf8'));
  users = data.users || [];
}

function saveDB() {
  fs.writeFileSync(dbFile, JSON.stringify({ users }, null, 2));
}

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

function generateToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
}

app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  if (users.find(u => u.email === email)) return res.status(400).json({ error: 'Email exists' });

  const hashedPassword = await bcrypt.hash(password, 12);
  const newUser = {
    id: Date.now(),
    name,
    email,
    password: hashedPassword,
    status: 'Active',
    cashValue: 52840,
    plan: 'Family Growth'
  };
  users.push(newUser);
  saveDB();

  const token = generateToken(newUser);
  res.json({ success: true, token, user: { ...newUser, password: undefined } });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
  const token = generateToken(user);
  res.json({ success: true, token, user: { ...user, password: undefined } });
});

app.get('/api/admin/users', (req, res) => {
  res.json({ users: users.map(u => ({ ...u, password: undefined })) });
});

app.listen(PORT, () => console.log(`Secure server running on port ${PORT}`));