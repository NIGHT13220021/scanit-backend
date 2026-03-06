const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const db = require('../db');
const { authenticate } = require('../middleware/auth');

router.post('/start', authenticate, async (req, res) => {
  const { store_qr_code } = req.body;
  if (!store_qr_code) return res.status(400).json({ error: 'Store QR code required' });
  try {
    const store = await db.query(
      'SELECT * FROM stores WHERE entry_qr_code = $1 AND is_active = true',
      [store_qr_code]
    );
    if (store.rows.length === 0) return res.status(404).json({ error: 'Invalid store QR code' });
    const storeData = store.rows[0];
    const existing = await db.query(
      "SELECT * FROM sessions WHERE user_id = $1 AND store_id = $2 AND status = 'active'",
      [req.user.id, storeData.id]
    );
    if (existing.rows.length > 0) {
      return res.json({ success: true, session: existing.rows[0], store: storeData });
    }
    const sessionCode = uuidv4();
    const session = await db.query(
      'INSERT INTO sessions (session_code, user_id, store_id) VALUES ($1, $2, $3) RETURNING *',
      [sessionCode, req.user.id, storeData.id]
    );
    res.json({
      success: true,
      session: session.rows[0],
      store: { id: storeData.id, name: storeData.name, city: storeData.city }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not start session' });
  }
});

router.get('/current', authenticate, async (req, res) => {
  try {
    const session = await db.query(
      `SELECT s.*, st.name as store_name FROM sessions s 
       JOIN stores st ON st.id = s.store_id 
       WHERE s.user_id = $1 AND s.status = 'active' 
       ORDER BY s.entry_time DESC LIMIT 1`,
      [req.user.id]
    );
    res.json({ session: session.rows[0] || null });
  } catch (error) {
    res.status(500).json({ error: 'Could not get session' });
  }
});

module.exports = router;