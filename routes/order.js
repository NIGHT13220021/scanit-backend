const express  = require('express');
const router   = express.Router();
const Razorpay = require('razorpay');
const crypto   = require('crypto');
const QRCode   = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const db       = require('../db');
const { authenticate } = require('../middleware/auth');
require('dotenv').config();

const razorpay = new Razorpay({
  key_id:     process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// ── POST /api/order/create ───────────────────────────────
router.post('/create', authenticate, async (req, res) => {
  const { session_id } = req.body;
  try {
    // Get cart total
    const cartTotal = await db.query(
      `SELECT SUM(ci.quantity * ci.price_at_scan) as total
       FROM cart_items ci
       JOIN sessions s ON s.id = ci.session_id
       WHERE ci.session_id = $1 AND s.user_id = $2 AND s.status = 'active'`,
      [session_id, req.user.id]
    );

    if (!cartTotal.rows[0].total)
      return res.status(400).json({ error: 'Cart is empty' });

    const total       = parseFloat(cartTotal.rows[0].total);
    const orderNumber = 'ORYN-' + Date.now();

    // Create Razorpay order
    const razorpayOrder = await razorpay.orders.create({
      amount:   Math.round(total * 100),
      currency: 'INR',
      receipt:  orderNumber,
    });

    // Create order in DB
    const order = await db.query(
      `INSERT INTO orders
         (order_number, session_id, user_id, store_id, total, subtotal, payment_status, razorpay_order_id)
       SELECT $1, $2, $3, store_id, $4, $4, 'pending', $5
       FROM sessions WHERE id = $2
       RETURNING *`,
      [orderNumber, session_id, req.user.id, total, razorpayOrder.id]
    );

    return res.json({
      success:           true,
      order_id:          order.rows[0].id,
      razorpay_order_id: razorpayOrder.id,
      amount:            razorpayOrder.amount,
      currency:          'INR',
      key_id:            process.env.RAZORPAY_KEY_ID,
    });

  } catch (error) {
    console.error('Create order error:', error.message);
    return res.status(500).json({ error: 'Could not create order' });
  }
});

// ── POST /api/order/verify ───────────────────────────────
router.post('/verify', authenticate, async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, order_id } = req.body;
  try {
    // Verify signature
    const expected = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(razorpay_order_id + '|' + razorpay_payment_id)
      .digest('hex');

    if (expected !== razorpay_signature)
      return res.status(400).json({ error: 'Payment verification failed' });

    // Generate exit QR
    const exitQRData   = uuidv4();
    const exitQRExpiry = new Date(Date.now() + 30 * 60 * 1000); // 30 mins
    const qrImage      = await QRCode.toDataURL(exitQRData);

    // Update order → paid
    await db.query(
      `UPDATE orders
       SET payment_status      = 'paid',
           razorpay_payment_id = $1,
           exit_qr_code        = $2,
           exit_qr_expires     = $3
       WHERE id = $4`,
      [razorpay_payment_id, exitQRData, exitQRExpiry, order_id]
    );

    // Get session_id from order
    const sessionResult = await db.query(
      `SELECT session_id FROM orders WHERE id = $1`,
      [order_id]
    );
    const session_id = sessionResult.rows[0]?.session_id;

    // Mark session completed + save stats
    if (session_id) {
      const cartStats = await db.query(
        `SELECT COUNT(*) as item_count, SUM(quantity * price_at_scan) as total
         FROM cart_items WHERE session_id = $1`,
        [session_id]
      );
      const stats = cartStats.rows[0];

      await db.query(
        `UPDATE sessions
         SET status        = 'completed',
             exit_time     = NOW(),
             payment_time  = NOW(),
             total_amount  = $1,
             item_count    = $2,
             duration_mins = ROUND(EXTRACT(EPOCH FROM (NOW() - entry_time))/60)
         WHERE id = $3`,
        [stats.total || 0, stats.item_count || 0, session_id]
      );
    }

    // Decrement stock_quantity for products that have it tracked
    try {
      await db.query(
        `UPDATE store_products sp
         SET stock_quantity = GREATEST(0, sp.stock_quantity - ci.quantity),
             in_stock    = (GREATEST(0, sp.stock_quantity - ci.quantity) > 0),
             is_available = (GREATEST(0, sp.stock_quantity - ci.quantity) > 0)
         FROM cart_items ci
         JOIN orders o ON o.session_id = ci.session_id
         WHERE o.id = $1
           AND sp.product_id = ci.product_id
           AND sp.store_id   = o.store_id
           AND sp.stock_quantity IS NOT NULL`,
        [order_id]
      );
    } catch (stockErr) {
      console.error('Stock decrement error (non-fatal):', stockErr.message);
    }

    return res.json({
      success:          true,
      exit_qr:          exitQRData,
      exit_qr_image:    qrImage,
      exit_qr_expires:  exitQRExpiry,
      message:          'Payment successful!',
    });

  } catch (error) {
    console.error('Verify payment error:', error.message);
    return res.status(500).json({ error: 'Payment verification failed' });
  }
});

// ── GET /api/order/history ───────────────────────────────
router.get('/history', authenticate, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT
         o.id, o.order_number, o.total, o.subtotal,
         o.payment_status, o.razorpay_payment_id, o.created_at,
         s.name as store_name,
         COALESCE(
           json_agg(
             json_build_object(
               'name',       p.name,
               'brand',      p.brand,
               'quantity',   ci.quantity,
               'price',      ci.price_at_scan,
               'item_total', ci.quantity * ci.price_at_scan
             )
           ) FILTER (WHERE p.id IS NOT NULL), '[]'
         ) as items
       FROM orders o
       LEFT JOIN stores s     ON s.id = o.store_id
       LEFT JOIN sessions ses ON ses.id = o.session_id
       LEFT JOIN cart_items ci ON ci.session_id = o.session_id
       LEFT JOIN products p   ON p.id = ci.product_id
       WHERE o.user_id = $1 AND o.payment_status = 'paid'
       GROUP BY o.id, s.name
       ORDER BY o.created_at DESC
       LIMIT 50`,
      [req.user.id]
    );

    return res.json({ success: true, orders: result.rows });

  } catch (error) {
    console.error('Order history error:', error.message);
    return res.status(500).json({ error: 'Could not fetch order history' });
  }
});

// ── GET /api/order/:id/receipt ───────────────────────────
router.get('/:id/receipt', authenticate, async (req, res) => {
  try {
    const orderResult = await db.query(
      `SELECT o.*, s.name as store_name
       FROM orders o
       JOIN stores s ON s.id = o.store_id
       WHERE o.id = $1 AND o.user_id = $2`,
      [req.params.id, req.user.id]
    );

    if (orderResult.rows.length === 0)
      return res.status(404).json({ error: 'Order not found' });

    const order = orderResult.rows[0];

    // Get items via session cart_items
    const itemsResult = await db.query(
      `SELECT
         ci.quantity,
         ci.price_at_scan as price,
         ci.quantity * ci.price_at_scan as item_total,
         p.name, p.brand, p.category, p.barcode
       FROM cart_items ci
       JOIN products p ON p.id = ci.product_id
       WHERE ci.session_id = $1
       ORDER BY p.name`,
      [order.session_id]
    );

    return res.json({
      success: true,
      order: {
        id:                  order.id,
        order_number:        order.order_number,
        store_name:          order.store_name,
        total:               order.total,
        payment_status:      order.payment_status,
        razorpay_payment_id: order.razorpay_payment_id,
        exit_qr_code:        order.exit_qr_code,
        exit_qr_expires:     order.exit_qr_expires,
        created_at:          order.created_at,
      },
      items: itemsResult.rows,
    });

  } catch (error) {
    console.error('Receipt error:', error.message);
    return res.status(500).json({ error: 'Could not load receipt' });
  }
});

// ── GET /api/order/:id ───────────────────────────────────
router.get('/:id', authenticate, async (req, res) => {
  try {
    const orderResult = await db.query(
      `SELECT o.*, s.name as store_name
       FROM orders o
       JOIN stores s ON s.id = o.store_id
       WHERE o.id = $1 AND o.user_id = $2`,
      [req.params.id, req.user.id]
    );

    if (orderResult.rows.length === 0)
      return res.status(404).json({ error: 'Order not found' });

    const order = orderResult.rows[0];

    const itemsResult = await db.query(
      `SELECT ci.quantity, ci.price_at_scan as price,
              ci.quantity * ci.price_at_scan as item_total,
              p.name, p.brand, p.category
       FROM cart_items ci
       JOIN products p ON p.id = ci.product_id
       WHERE ci.session_id = $1`,
      [order.session_id]
    );

    return res.json({
      success: true,
      order: {
        id:                  order.id,
        order_number:        order.order_number,
        store_name:          order.store_name,
        total:               order.total,
        payment_status:      order.payment_status,
        razorpay_payment_id: order.razorpay_payment_id,
        created_at:          order.created_at,
      },
      items: itemsResult.rows,
    });

  } catch (error) {
    console.error('Get order error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch order' });
  }
});

// ── Auto-fail pending orders older than 30 mins ──────────
const cleanPendingOrders = async () => {
  try {
    await db.query(
      `UPDATE orders SET payment_status = 'failed'
       WHERE payment_status = 'pending'
         AND razorpay_payment_id IS NULL
         AND created_at < NOW() - INTERVAL '30 minutes'`
    );
  } catch (e) {
    console.error('Clean pending orders error:', e.message);
  }
};
setInterval(cleanPendingOrders, 15 * 60 * 1000);
cleanPendingOrders();

module.exports = router;