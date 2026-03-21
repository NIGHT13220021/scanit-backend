const express = require('express');
const router  = express.Router();
const { v4: uuidv4 } = require('uuid');
const db      = require('../db');
const { authenticate } = require('../middleware/auth');

const THREE_HOURS = 3 * 60 * 60 * 1000; // 3 hours in ms

// ── POST /api/session/start ──────────────────────────────
router.post('/start', authenticate, async (req, res) => {
  const { store_qr_code } = req.body;
  if (!store_qr_code)
    return res.status(400).json({ error: 'Store QR code required' });

  try {
    // Find store
    const store = await db.query(
      'SELECT * FROM stores WHERE entry_qr_code = $1 AND is_active = true',
      [store_qr_code]
    );
    if (store.rows.length === 0)
      return res.status(404).json({ error: 'Invalid or inactive store QR code' });

    const storeData = store.rows[0];

    // ── Look for recent ACTIVE or ABANDONED session (SAME STORE, < 3 hours) ──
    // NEVER reactivate EXPIRED sessions — they are dead
    const recent = await db.query(
      `SELECT s.*, st.name as store_name
       FROM sessions s
       JOIN stores st ON st.id = s.store_id
       WHERE s.user_id   = $1
         AND s.store_id  = $2
         AND s.status    IN ('active', 'abandoned')
         AND s.entry_time > NOW() - INTERVAL '3 hours'
       ORDER BY s.entry_time DESC
       LIMIT 1`,
      [req.user.id, storeData.id]
    );

    if (recent.rows.length > 0) {
      // Session < 3 hours old → REACTIVATE
      const s = recent.rows[0];
      const reactivated = await db.query(
        `UPDATE sessions
         SET status = 'active', exit_time = NULL
         WHERE id = $1
         RETURNING *`,
        [s.id]
      );
      return res.json({
        success:  true,
        resumed:  true,
        session:  { ...reactivated.rows[0], store_name: storeData.name },
        store:    { id: storeData.id, name: storeData.name, city: storeData.city }
      });
    }

    // ── No recent session found → expire any old active sessions first ──
    // Then create fresh session
    await db.query(
      `UPDATE sessions
       SET status = 'expired', exit_time = NOW(),
           duration_mins = ROUND(EXTRACT(EPOCH FROM (NOW() - entry_time))/60)
       WHERE user_id = $1
         AND store_id = $2
         AND status IN ('active', 'abandoned')`,
      [req.user.id, storeData.id]
    );

    // Also abandon any active session at a DIFFERENT store
    await db.query(
      `UPDATE sessions
       SET status = 'abandoned', exit_time = NOW(),
           duration_mins = ROUND(EXTRACT(EPOCH FROM (NOW() - entry_time))/60)
       WHERE user_id  = $1
         AND store_id != $2
         AND status   = 'active'`,
      [req.user.id, storeData.id]
    );

    // Create FRESH session
    const session = await db.query(
      `INSERT INTO sessions (session_code, user_id, store_id, status, entry_time)
       VALUES ($1, $2, $3, 'active', NOW()) RETURNING *`,
      [uuidv4(), req.user.id, storeData.id]
    );

    return res.json({
      success: true,
      resumed: false,
      session: { ...session.rows[0], store_name: storeData.name },
      store:   { id: storeData.id, name: storeData.name, city: storeData.city }
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
      `SELECT s.*, st.name as store_name
       FROM sessions s
       JOIN stores st ON st.id = s.store_id
       WHERE s.user_id = $1
         AND s.status  = 'active'
       ORDER BY s.entry_time DESC LIMIT 1`,
      [req.user.id]
    );
    return res.json({ session: session.rows[0] || null });
  } catch (error) {
    return res.status(500).json({ error: 'Could not get session' });
  }
});

// ── POST /api/session/end ────────────────────────────────
// reason: 'abandoned' (background) | 'user_exit' (tapped End) | 'expired' (force expire)
router.post('/end', authenticate, async (req, res) => {
  try {
    const { reason = 'abandoned' } = req.body;

    // user_exit → mark expired so resume banner disappears
    const newStatus = reason === 'user_exit' ? 'expired'
                    : reason === 'completed' ? 'completed'
                    : 'abandoned';

    const result = await db.query(
      `UPDATE sessions
       SET status = $1, exit_time = NOW(),
           duration_mins = ROUND(EXTRACT(EPOCH FROM (NOW() - entry_time))/60)
       WHERE user_id = $2 AND status = 'active'
       RETURNING *`,
      [newStatus, req.user.id]
    );

    if (result.rows.length === 0)
      return res.json({ success: true, message: 'No active session' });

    return res.json({ success: true, session: result.rows[0] });

  } catch (error) {
    console.error('Session end error:', error.message);
    return res.status(500).json({ error: 'Could not end session' });
  }
});

// ── POST /api/session/complete ───────────────────────────
router.post('/complete', authenticate, async (req, res) => {
  try {
    const { session_id, total_amount, item_count } = req.body;
    const result = await db.query(
      `UPDATE sessions
       SET status = 'completed', exit_time = NOW(), payment_time = NOW(),
           total_amount = $1, item_count = $2,
           duration_mins = ROUND(EXTRACT(EPOCH FROM (NOW() - entry_time))/60)
       WHERE id = $3 AND user_id = $4
       RETURNING *`,
      [total_amount || 0, item_count || 0, session_id, req.user.id]
    );
    return res.json({ success: true, session: result.rows[0] });
  } catch (error) {
    console.error('Session complete error:', error.message);
    return res.status(500).json({ error: 'Could not complete session' });
  }
});

// ── GET /api/store/:store_id/qr-value ───────────────────
router.get('/store/:store_id/qr-value', authenticate, async (req, res) => {
  try {
    const store = await db.query(
      'SELECT entry_qr_code, name FROM stores WHERE id = $1 AND is_active = true',
      [req.params.store_id]
    );
    if (store.rows.length === 0)
      return res.status(404).json({ error: 'Store not found' });
    return res.json({ success: true, qr_code_value: store.rows[0].entry_qr_code, store_name: store.rows[0].name });
  } catch (e) {
    return res.status(500).json({ error: 'Could not get store QR' });
  }
});

// ── AUTO-EXPIRE — runs every 5 mins ─────────────────────
const autoExpire = async () => {
  try {
    // 1. Expire sessions with NO cart items after 30 mins
    const r1 = await db.query(
      `UPDATE sessions
       SET status = 'expired', exit_time = NOW(),
           duration_mins = ROUND(EXTRACT(EPOCH FROM (NOW() - entry_time))/60)
       WHERE status = 'active'
         AND entry_time < NOW() - INTERVAL '30 minutes'
         AND id NOT IN (SELECT DISTINCT session_id FROM cart_items)
       RETURNING id`
    );

    // 2. Expire ALL sessions older than 3 hours (regardless of cart)
    const r2 = await db.query(
      `UPDATE sessions
       SET status = 'expired', exit_time = NOW(),
           duration_mins = ROUND(EXTRACT(EPOCH FROM (NOW() - entry_time))/60)
       WHERE status IN ('active', 'abandoned')
         AND entry_time < NOW() - INTERVAL '3 hours'
       RETURNING id`
    );

    if (r1.rows.length > 0) console.log(`Auto-expired ${r1.rows.length} empty sessions`);
    if (r2.rows.length > 0) console.log(`Auto-expired ${r2.rows.length} old sessions`);
  } catch (e) {
    console.error('Auto-expire error:', e.message);
  }
};
setInterval(autoExpire, 5 * 60 * 1000);
autoExpire();

module.exports = router;