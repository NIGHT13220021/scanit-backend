const express = require('express');
const router = express.Router();
const Razorpay = require('razorpay');
const crypto = require('crypto');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const db = require('../db');
const { authenticate } = require('../middleware/auth');
require('dotenv').config();

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

router.post('/create', authenticate, async (req, res) => {
  const { session_id } = req.body;
  try {
    const cartTotal = await db.query(
      `SELECT SUM(ci.quantity * ci.price_at_scan) as total FROM cart_items ci
       JOIN sessions s ON s.id = ci.session_id
       WHERE ci.session_id = $1 AND s.user_id = $2 AND s.status = 'active'`,
      [session_id, req.user.id]
    );
    if (!cartTotal.rows[0].total) return res.status(400).json({ error: 'Cart is empty' });

    const total = parseFloat(cartTotal.rows[0].total);
    const orderNumber = 'ORD-' + Date.now();

    const razorpayOrder = await razorpay.orders.create({
      amount: Math.round(total * 100),
      currency: 'INR',
      receipt: orderNumber,
    });

    const order = await db.query(
      `INSERT INTO orders (order_number, session_id, user_id, store_id, total, subtotal, payment_status, razorpay_order_id)
       SELECT $1, $2, $3, store_id, $4, $4, 'pending', $5 FROM sessions WHERE id = $2 RETURNING *`,
      [orderNumber, session_id, req.user.id, total, razorpayOrder.id]
    );

    res.json({
      success: true,
      order_id: order.rows[0].id,
      razorpay_order_id: razorpayOrder.id,
      amount: razorpayOrder.amount,
      currency: 'INR',
      key_id: process.env.RAZORPAY_KEY_ID
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not create order' });
  }
});

router.post('/verify', authenticate, async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, order_id } = req.body;
  try {
    const expected = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(razorpay_order_id + '|' + razorpay_payment_id)
      .digest('hex');

    if (expected !== razorpay_signature) {
      return res.status(400).json({ error: 'Payment verification failed' });
    }

    const exitQRData = uuidv4();
    const exitQRExpiry = new Date(Date.now() + 30 * 60 * 1000);
    const qrImage = await QRCode.toDataURL(exitQRData);

    await db.query(
      `UPDATE orders SET payment_status = 'paid', razorpay_payment_id = $1,
       exit_qr_code = $2, exit_qr_expires = $3 WHERE id = $4`,
      [razorpay_payment_id, exitQRData, exitQRExpiry, order_id]
    );

    await db.query(
      "UPDATE sessions SET status = 'paid' WHERE id = (SELECT session_id FROM orders WHERE id = $1)",
      [order_id]
    );

    res.json({
      success: true,
      exit_qr: exitQRData,
      exit_qr_image: qrImage,
      exit_qr_expires: exitQRExpiry,
      message: 'Payment successful!'
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Payment verification failed' });
  }
});

router.get('/history/all', authenticate, async (req, res) => {
  try {
    const orders = await db.query(
      `SELECT o.id, o.order_number, o.total, o.payment_status, o.created_at, s.name as store_name
       FROM orders o JOIN stores s ON s.id = o.store_id
       WHERE o.user_id = $1 ORDER BY o.created_at DESC LIMIT 20`,
      [req.user.id]
    );
    res.json({ orders: orders.rows });
  } catch (error) {
    res.status(500).json({ error: 'Could not get orders' });
  }
});



// ✅ ADD THIS ROUTE to your routes/order.js file
// GET /api/order/history — returns all past orders for logged-in user

router.get('/history', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;

    const result = await db.query(
      `SELECT 
        o.id,
        o.order_number,
        o.total,
        o.subtotal,
        o.payment_status,
        o.razorpay_payment_id,
        o.created_at,
        s.name as store_name,
        COALESCE(
          json_agg(
            json_build_object(
              'name', p.name,
              'brand', p.brand,
              'quantity', ci.quantity,
              'price', ci.price,
              'item_total', ci.quantity * ci.price
            )
          ) FILTER (WHERE p.id IS NOT NULL),
          '[]'
        ) as items
      FROM orders o
      LEFT JOIN stores s ON s.id = o.store_id
      LEFT JOIN sessions ses ON ses.id = o.session_id
      LEFT JOIN cart_items ci ON ci.session_id = o.session_id
      LEFT JOIN products p ON p.id = ci.product_id
      WHERE o.user_id = $1
      GROUP BY o.id, s.name
      ORDER BY o.created_at DESC`,
      [userId]
    );

    res.json({ orders: result.rows });
  } catch (error) {
    console.error('Order history error:', error);
    res.status(500).json({ error: 'Could not fetch order history' });
  }
});

module.exports = router;