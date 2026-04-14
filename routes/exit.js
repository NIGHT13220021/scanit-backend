const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const db = require('../db');
const { authenticate } = require('../middleware/auth');

// ✅ GET exit code for session (requires customer auth)
router.get('/code/:sessionId', authenticate, async (req, res) => {
  const { sessionId } = req.params;
  try {
    const result = await db.query(
      `SELECT exit_qr_code, exit_qr_expires, payment_status 
       FROM orders 
       WHERE session_id = $1 
       ORDER BY created_at DESC 
       LIMIT 1`,
      [sessionId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No order found for this session' });
    }

    const order = result.rows[0];

    if (order.payment_status !== 'paid') {
      return res.status(400).json({ error: 'Payment not completed' });
    }

    res.json({
      exit_code: order.exit_qr_code,
      exit_qr_expires: order.exit_qr_expires, // ✅ send expiry to frontend
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not fetch exit code' });
  }
});

// ✅ NEW — regenerate a fresh exit QR if expired
router.post('/regenerate/:sessionId', authenticate, async (req, res) => {
  const { sessionId } = req.params;
  try {
    // verify payment is paid
    const check = await db.query(
      `SELECT id, payment_status FROM orders 
       WHERE session_id = $1 
       ORDER BY created_at DESC LIMIT 1`,
      [sessionId]
    );

    if (check.rows.length === 0) {
      return res.status(404).json({ error: 'No order found' });
    }

    if (check.rows[0].payment_status !== 'paid') {
      return res.status(400).json({ error: 'Payment not completed' });
    }

    const orderId = check.rows[0].id;
    const newExitCode = uuidv4();
    const newExpiry = new Date(Date.now() + 30 * 60 * 1000); // fresh 30 mins

    await db.query(
      `UPDATE orders SET exit_qr_code = $1, exit_qr_expires = $2 WHERE id = $3`,
      [newExitCode, newExpiry, orderId]
    );

    res.json({
      exit_code: newExitCode,
      exit_qr_expires: newExpiry,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not regenerate exit QR' });
  }
});

// ✅ EXISTING — guard scans QR to verify
router.post('/verify', async (req, res) => {
  const { exit_qr } = req.body;
  try {
    const result = await db.query(
      `SELECT o.id, o.total, o.payment_status, o.exit_qr_expires,
              o.order_number, o.session_id, o.store_id,
              COUNT(ci.id) as item_count
       FROM orders o
       LEFT JOIN cart_items ci ON ci.session_id = o.session_id
       WHERE o.exit_qr_code = $1
       GROUP BY o.id`,
      [exit_qr]
    );

    if (result.rows.length === 0) {
      return res.json({
        valid:        false,
        flag:         true,
        flag_reason:  'Invalid QR code — not found in system',
        message:      'Invalid QR code'
      });
    }

    const order = result.rows[0];
    // Anonymous session code shown to guard instead of phone number
    const session_code = `#${String(order.id).padStart(4, '0')}`;

    if (new Date() > new Date(order.exit_qr_expires)) {
      return res.json({
        valid:        false,
        flag:         true,
        flag_reason:  'QR code has expired',
        session_code,
        message:      'QR code expired'
      });
    }

    if (order.payment_status !== 'paid') {
      return res.json({
        valid:        false,
        flag:         true,
        flag_reason:  'Payment not completed',
        session_code,
        items:        parseInt(order.item_count) || 0,
        amount:       order.total,
        message:      'Payment not completed'
      });
    }

    // Valid — no personal details, just what staff needs
    res.json({
      valid:        true,
      message:      'GO',
      session_code,
      amount_paid:  order.total,
      items:        parseInt(order.item_count) || 0,
      order_number: order.order_number
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not verify QR' });
  }
});

module.exports = router;