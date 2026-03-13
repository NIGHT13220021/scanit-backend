const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

app.use('/api/auth',    require('./routes/auth'));
app.use('/api/session', require('./routes/session'));
app.use('/api/product', require('./routes/product'));
app.use('/api/cart',    require('./routes/cart'));
app.use('/api/order',   require('./routes/order'));
app.use('/api/exit',    require('./routes/exit'));
app.use('/api/admin',   require('./routes/admin'));

app.get('/health', (req, res) => {
  res.json({ status: 'OK', message: 'ScanIt API running', time: new Date() });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n✅ ScanIt Backend running on port ${PORT}`);
  console.log(`🌐 http://localhost:${PORT}/health\n`);
});
setInterval(async () => {
  try {
    const http = require('http');
    http.get('http://localhost:' + PORT + '/health', () => {});
    console.log('🏓 Self ping to stay awake');
  } catch(e) {}
}, 14 * 60 * 1000);