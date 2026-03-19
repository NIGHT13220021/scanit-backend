const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const db = require('../db');
const { authenticate } = require('../middleware/auth');

// ── POST /api/session/start ──────────────────────────────
router.post('/start', authenticate, async (req, res) => {
  const { store_qr_code } = req.body;
  if (!store_qr_code) return res.status(400).json({ error: 'Store QR code required' });

  try {
    const store = await db.query(
      'SELECT * FROM stores WHERE entry_qr_code = $1 AND is_active = true',
      [store_qr_code]
    );
    if (store.rows.length === 0)
      return res.status(404).json({ error: 'Invalid or inactive store QR code' });

    const storeData = store.rows[0];

    // Check existing active session
    const existing = await db.query(
      `SELECT s.*, st.name as store_name 
       FROM sessions s
       JOIN stores st ON st.id = s.store_id
       WHERE s.user_id = $1 AND s.status = 'active'`,
      [req.user.id]
    );

    if (existing.rows.length > 0) {
      const s = existing.rows[0];
      // Same store — resume existing session
      if (s.store_id === storeData.id) {
        return res.json({
          success: true, resumed: true,
          session: s,
          store: { id: storeData.id, name: storeData.name, city: storeData.city }
        });
      }
      // Different store — abandon old, start new
      await db.query(
        `UPDATE sessions SET status='abandoned', exit_time=NOW(),
         duration_mins=ROUND(EXTRACT(EPOCH FROM (NOW()-entry_time))/60)
         WHERE id=$1`,
        [s.id]
      );
    }

    // Create new session
    const session = await db.query(
      `INSERT INTO sessions (session_code, user_id, store_id, status, entry_time)
       VALUES ($1,$2,$3,'active',NOW()) RETURNING *`,
      [uuidv4(), req.user.id, storeData.id]
    );

    return res.json({
      success: true, resumed: false,
      session: { ...session.rows[0], store_name: storeData.name },
      store: { id: storeData.id, name: storeData.name, city: storeData.city }
    });

  } catch (error) {
    console.error('Session start error:', error.message);
    return res.status(500).json({ error: 'Could not start session' });
  }
});

// ── GET /api/session/current ─────────────────────────────
router.get('/current', authenticate, async (req, res) => {
  try {
    const session = await db.query(
      `SELECT s.*, st.name as store_name FROM sessions s
       JOIN stores st ON st.id = s.store_id
       WHERE s.user_id=$1 AND s.status='active'
       ORDER BY s.entry_time DESC LIMIT 1`,
      [req.user.id]
    );
    return res.json({ session: session.rows[0] || null });
  } catch (error) {
    return res.status(500).json({ error: 'Could not get session' });
  }
});

// ── POST /api/session/end ────────────────────────────────
// Called when app goes background or user manually ends
router.post('/end', authenticate, async (req, res) => {
  try {
    const { reason = 'abandoned' } = req.body;

    const result = await db.query(
      `UPDATE sessions
       SET status=$1, exit_time=NOW(),
           duration_mins=ROUND(EXTRACT(EPOCH FROM (NOW()-entry_time))/60)
       WHERE user_id=$2 AND status='active'
       RETURNING *`,
      [reason === 'completed' ? 'completed' : 'abandoned', req.user.id]
    );

    if (result.rows.length === 0) {
      return res.json({ success: true, message: 'No active session' });
    }

    return res.json({ success: true, session: result.rows[0] });

  } catch (error) {
    console.error('Session end error:', error.message);
    return res.status(500).json({ error: 'Could not end session' });
  }
});

// ── POST /api/session/complete ───────────────────────────
// Called after successful payment
router.post('/complete', authenticate, async (req, res) => {
  try {
    const { session_id, total_amount, item_count } = req.body;

    const result = await db.query(
      `UPDATE sessions
       SET status='completed', exit_time=NOW(), payment_time=NOW(),
           total_amount=$1, item_count=$2,
           duration_mins=ROUND(EXTRACT(EPOCH FROM (NOW()-entry_time))/60)
       WHERE id=$3 AND user_id=$4
       RETURNING *`,
      [total_amount || 0, item_count || 0, session_id, req.user.id]
    );

    return res.json({ success: true, session: result.rows[0] });

  } catch (error) {
    console.error('Session complete error:', error.message);
    return res.status(500).json({ error: 'Could not complete session' });
  }
});

// ── Auto-expire sessions older than 3 hours ──────────────
const autoExpire = async () => {
  try {
    const result = await db.query(
      `UPDATE sessions
       SET status='expired', exit_time=NOW(),
           duration_mins=ROUND(EXTRACT(EPOCH FROM (NOW()-entry_time))/60)
       WHERE status='active' AND entry_time < NOW() - INTERVAL '3 hours'
       RETURNING id`
    );
    if (result.rows.length > 0)
      console.log(`Auto-expired ${result.rows.length} sessions`);
  } catch (e) {
    console.error('Auto-expire error:', e.message);
  }
};
setInterval(autoExpire, 15 * 60 * 1000);
autoExpire();

module.exports = router;