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
      `SELECT o.*, u.phone FROM orders o 
       JOIN users u ON u.id = o.user_id
       WHERE o.exit_qr_code = $1`,
      [exit_qr]
    );

    if (result.rows.length === 0) {
      return res.json({ valid: false, message: 'Invalid QR code' });
    }

    const order = result.rows[0];

    if (new Date() > new Date(order.exit_qr_expires)) {
      return res.json({ valid: false, message: 'QR code expired' });
    }

    if (order.payment_status !== 'paid') {
      return res.json({ valid: false, message: 'Payment not completed' });
    }

    res.json({
      valid: true,
      message: 'GO ✅',
      customer_phone: order.phone,
      amount_paid: order.total,
      order_number: order.order_number
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not verify QR' });
  }
});

module.exports = router;