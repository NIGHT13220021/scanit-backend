const express = require('express');
const router = express.Router();
const db = require('../db');
const { authenticate } = require('../middleware/auth');

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