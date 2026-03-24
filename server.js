const express = require('express');
const cors    = require('cors');
require('dotenv').config();

const { authenticate } = require('./middleware/auth'); // ← ADD THIS

const app  = express();
const PORT = process.env.PORT || 5000;

app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*', // lock down in production
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
}));
app.use(express.json());

// ── Public routes (no token needed) ──
app.use('/api/auth',    require('./routes/auth'));
app.use('/api/product', require('./routes/product')); // browsing is public

// ── Protected routes (token required) ──
app.use('/api/session', authenticate, require('./routes/session'));
app.use('/api/cart',    authenticate, require('./routes/cart'));
app.use('/api/order',   authenticate, require('./routes/order'));
app.use('/api/exit',    authenticate, require('./routes/exit'));
app.use('/api/admin',   authenticate, require('./routes/admin'));

// ── Health check ──
app.get('/health', (req, res) => {
  res.json({ status: 'OK', message: 'ScanIt API running', time: new Date() });
});

// ── Global error handler ──
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Something went wrong' });
});

// ── Start server ──
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ ScanIt Backend running on port ${PORT}`);
  console.log(`🌐 http://localhost:${PORT}/health`);
});

// ── Self-ping (only if SELF_PING=true in .env, e.g. on Render free tier) ──
server.on('listening', () => {
  if (process.env.SELF_PING === 'true') {
    setInterval(() => {
      require('http').get(`http://127.0.0.1:${PORT}/health`).on('error', () => {});
      console.log('🏓 Self ping to stay awake');
    }, 14 * 60 * 1000);
  }
});