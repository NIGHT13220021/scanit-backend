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

    const razorpayOrder = await razorpay.orders.create({
      amount:   Math.round(total * 100),
      currency: 'INR',
      receipt:  orderNumber,
    });

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
    const expected = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(razorpay_order_id + '|' + razorpay_payment_id)
      .digest('hex');

    if (expected !== razorpay_signature)
      return res.status(400).json({ error: 'Payment verification failed' });

    const exitQRData   = uuidv4();
    const exitQRExpiry = new Date(Date.now() + 30 * 60 * 1000);
    const qrImage      = await QRCode.toDataURL(exitQRData);

    await db.query(
      `UPDATE orders
       SET payment_status      = 'paid',
           razorpay_payment_id = $1,
           exit_qr_code        = $2,
           exit_qr_expires     = $3
       WHERE id = $4`,
      [razorpay_payment_id, exitQRData, exitQRExpiry, order_id]
    );

    const sessionResult = await db.query(
      `SELECT session_id FROM orders WHERE id = $1`, [order_id]
    );
    const session_id = sessionResult.rows[0]?.session_id;

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

    // ── Decrement stock after payment ──────────────────────
    try {
      await db.query(
        `UPDATE store_products sp
         SET stock_quantity = GREATEST(0, sp.stock_quantity - ci.quantity),
             in_stock       = (GREATEST(0, sp.stock_quantity - ci.quantity) > 0),
             is_available   = (GREATEST(0, sp.stock_quantity - ci.quantity) > 0)
         FROM cart_items ci
         JOIN orders o ON o.session_id = ci.session_id
         WHERE o.id = $1
           AND sp.product_id  = ci.product_id
           AND sp.store_id    = o.store_id
           AND sp.stock_quantity IS NOT NULL`,
        [order_id]
      );
    } catch (stockErr) {
      console.error('Stock decrement error (non-fatal):', stockErr.message);
    }

    return res.json({
      success:         true,
      exit_qr:         exitQRData,
      exit_qr_image:   qrImage,
      exit_qr_expires: exitQRExpiry,
      message:         'Payment successful!',
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
               'name',        p.name,
               'brand',       p.brand,
               'quantity',    ci.quantity,
               'price',       ci.price_at_scan,
               'item_total',  ci.quantity * ci.price_at_scan,
               'gst_percent', COALESCE(sp.gst_percent, 0)
             )
           ) FILTER (WHERE p.id IS NOT NULL), '[]'
         ) as items
       FROM orders o
       LEFT JOIN stores s         ON s.id = o.store_id
       LEFT JOIN sessions ses     ON ses.id = o.session_id
       LEFT JOIN cart_items ci    ON ci.session_id = o.session_id
       LEFT JOIN products p       ON p.id = ci.product_id
       LEFT JOIN store_products sp ON sp.product_id = p.id AND sp.store_id = o.store_id
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
// ✅ Now includes gst_percent per item from store_products
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

    // ✅ Join store_products to get gst_percent per item
    const itemsResult = await db.query(
      `SELECT
         ci.quantity,
         ci.price_at_scan                        AS price,
         ci.quantity * ci.price_at_scan           AS item_total,
         p.name,
         p.brand,
         p.category,
         p.barcode,
         COALESCE(sp.gst_percent, 0)              AS gst_percent,
         -- GST breakdown (price is GST-inclusive)
         ROUND(
           (ci.price_at_scan / (1 + COALESCE(sp.gst_percent,0)/100)) * ci.quantity, 2
         )                                        AS base_amount,
         ROUND(
           ci.price_at_scan * ci.quantity
           - (ci.price_at_scan / (1 + COALESCE(sp.gst_percent,0)/100)) * ci.quantity, 2
         )                                        AS gst_amount
       FROM cart_items ci
       JOIN products p        ON p.id  = ci.product_id
       LEFT JOIN store_products sp
              ON sp.product_id = p.id
             AND sp.store_id   = $2
       WHERE ci.session_id = $1
       ORDER BY p.name`,
      [order.session_id, order.store_id]
    );

    // ── Bill summary ──────────────────────────────────────
    const items      = itemsResult.rows;
    const subtotal   = items.reduce((s, i) => s + parseFloat(i.base_amount || 0), 0);
    const totalGst   = items.reduce((s, i) => s + parseFloat(i.gst_amount  || 0), 0);
    const grandTotal = subtotal + totalGst; // should match order.total

    // GST slab breakdown (CGST + SGST split)
    const gstSlabs = {};
    items.forEach(item => {
      const rate = parseFloat(item.gst_percent || 0);
      const key  = `${rate}`;
      if (!gstSlabs[key]) gstSlabs[key] = { rate, taxable: 0, cgst: 0, sgst: 0, total_gst: 0 };
      const gstAmt = parseFloat(item.gst_amount || 0);
      gstSlabs[key].taxable   += parseFloat(item.base_amount || 0);
      gstSlabs[key].cgst      += gstAmt / 2;
      gstSlabs[key].sgst      += gstAmt / 2;
      gstSlabs[key].total_gst += gstAmt;
    });

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
      items,
      bill_summary: {
        subtotal:    subtotal.toFixed(2),
        total_gst:   totalGst.toFixed(2),
        grand_total: grandTotal.toFixed(2),
        cgst:        (totalGst / 2).toFixed(2),
        sgst:        (totalGst / 2).toFixed(2),
        gst_slabs:   Object.values(gstSlabs).map(g => ({
          rate:       g.rate,
          taxable:    g.taxable.toFixed(2),
          cgst:       g.cgst.toFixed(2),
          sgst:       g.sgst.toFixed(2),
          total_gst:  g.total_gst.toFixed(2),
        })),
      },
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
              p.name, p.brand, p.category,
              COALESCE(sp.gst_percent, 0) AS gst_percent
       FROM cart_items ci
       JOIN products p        ON p.id  = ci.product_id
       LEFT JOIN store_products sp
              ON sp.product_id = p.id AND sp.store_id = $2
       WHERE ci.session_id = $1`,
      [order.session_id, order.store_id]
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

// ── POST /api/order/upi-pay (create + mark paid in one shot) ─
router.post('/upi-pay', authenticate, async (req, res) => {
  const { session_id } = req.body;
  try {
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

    const order = await db.query(
      `INSERT INTO orders
         (order_number, session_id, user_id, store_id, total, subtotal, payment_status, payment_method)
       SELECT $1, $2, $3, store_id, $4, $4, 'paid', 'upi'
       FROM sessions WHERE id = $2
       RETURNING *`,
      [orderNumber, session_id, req.user.id, total]
    );

    const order_id = order.rows[0].id;

    // Update session
    const cartStats = await db.query(
      `SELECT COUNT(*) as item_count, SUM(quantity * price_at_scan) as total
       FROM cart_items WHERE session_id = $1`, [session_id]
    );
    const stats = cartStats.rows[0];
    await db.query(
      `UPDATE sessions
       SET status='completed', exit_time=NOW(), payment_time=NOW(),
           total_amount=$1, item_count=$2,
           duration_mins=ROUND(EXTRACT(EPOCH FROM (NOW()-entry_time))/60)
       WHERE id=$3`,
      [stats.total || 0, stats.item_count || 0, session_id]
    );

    // Decrement stock
    try {
      await db.query(
        `UPDATE store_products sp
         SET stock_quantity = GREATEST(0, sp.stock_quantity - ci.quantity),
             in_stock       = (GREATEST(0, sp.stock_quantity - ci.quantity) > 0),
             is_available   = (GREATEST(0, sp.stock_quantity - ci.quantity) > 0)
         FROM cart_items ci JOIN orders o ON o.session_id = ci.session_id
         WHERE o.id=$1 AND sp.product_id=ci.product_id
           AND sp.store_id=o.store_id AND sp.stock_quantity IS NOT NULL`,
        [order_id]
      );
    } catch (e) { console.error('Stock decrement (non-fatal):', e.message); }

    return res.json({ success: true, order_id, order_number: orderNumber, amount: total });
  } catch (error) {
    console.error('UPI pay error:', error.message);
    return res.status(500).json({ error: 'Could not process UPI payment' });
  }
});

// ── POST /api/order/create-upi ───────────────────────────
router.post('/create-upi', authenticate, async (req, res) => {
  const { session_id } = req.body;
  try {
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

    const order = await db.query(
      `INSERT INTO orders
         (order_number, session_id, user_id, store_id, total, subtotal, payment_status, payment_method)
       SELECT $1, $2, $3, store_id, $4, $4, 'pending', 'upi'
       FROM sessions WHERE id = $2
       RETURNING *`,
      [orderNumber, session_id, req.user.id, total]
    );

    return res.json({
      success:      true,
      order_id:     order.rows[0].id,
      order_number: orderNumber,
      amount:       total,
    });

  } catch (error) {
    console.error('Create UPI order error:', error.message);
    return res.status(500).json({ error: 'Could not create order' });
  }
});

// ── POST /api/order/upi-confirm ──────────────────────────
router.post('/upi-confirm', authenticate, async (req, res) => {
  const { order_id } = req.body;
  try {
    const orderCheck = await db.query(
      `SELECT * FROM orders
       WHERE id = $1 AND user_id = $2
         AND payment_method = 'upi' AND payment_status = 'pending'`,
      [order_id, req.user.id]
    );

    if (orderCheck.rows.length === 0)
      return res.status(404).json({ error: 'Order not found or already processed' });

    await db.query(
      `UPDATE orders SET payment_status = 'paid' WHERE id = $1`,
      [order_id]
    );

    const sessionResult = await db.query(
      `SELECT session_id FROM orders WHERE id = $1`, [order_id]
    );
    const session_id = sessionResult.rows[0]?.session_id;

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

    try {
      await db.query(
        `UPDATE store_products sp
         SET stock_quantity = GREATEST(0, sp.stock_quantity - ci.quantity),
             in_stock       = (GREATEST(0, sp.stock_quantity - ci.quantity) > 0),
             is_available   = (GREATEST(0, sp.stock_quantity - ci.quantity) > 0)
         FROM cart_items ci
         JOIN orders o ON o.session_id = ci.session_id
         WHERE o.id = $1
           AND sp.product_id  = ci.product_id
           AND sp.store_id    = o.store_id
           AND sp.stock_quantity IS NOT NULL`,
        [order_id]
      );
    } catch (stockErr) {
      console.error('Stock decrement error (non-fatal):', stockErr.message);
    }

    return res.json({ success: true, message: 'UPI payment confirmed!', order_id });

  } catch (error) {
    console.error('UPI confirm error:', error.message);
    return res.status(500).json({ error: 'Could not confirm payment' });
  }
});

// ── POST /api/order/cash-request ─────────────────────────
// Creates a pending cash order and returns a short code for the cashier
router.post('/cash-request', authenticate, async (req, res) => {
  const { session_id } = req.body;
  try {
    const cartTotal = await db.query(
      `SELECT SUM(ci.quantity * ci.price_at_scan) as total
       FROM cart_items ci
       JOIN sessions s ON s.id = ci.session_id
       WHERE ci.session_id = $1 AND s.user_id = $2 AND s.status = 'active'`,
      [session_id, req.user.id]
    );
    if (!cartTotal.rows[0].total)
      return res.status(400).json({ error: 'Cart is empty' });

    // Cancel any existing pending cash orders for this session
    await db.query(
      `UPDATE orders SET payment_status = 'cancelled'
       WHERE session_id = $1 AND payment_method = 'cash' AND payment_status = 'pending'`,
      [session_id]
    );

    const total       = parseFloat(cartTotal.rows[0].total);
    const orderNumber = 'ORYN-' + Date.now();
    // 4-digit numeric code, easy for cashier to read/type
    const cashCode    = String(Math.floor(1000 + Math.random() * 9000));

    const order = await db.query(
      `INSERT INTO orders
         (order_number, session_id, user_id, store_id, total, subtotal, payment_status, payment_method, cash_code)
       SELECT $1, $2, $3, store_id, $4, $4, 'pending', 'cash', $5
       FROM sessions WHERE id = $2
       RETURNING *`,
      [orderNumber, session_id, req.user.id, total, cashCode]
    );

    return res.json({
      success:      true,
      order_id:     order.rows[0].id,
      order_number: orderNumber,
      cash_code:    cashCode,
      amount:       total,
    });
  } catch (error) {
    console.error('Cash request error:', error.message);
    return res.status(500).json({ error: 'Could not create cash order' });
  }
});

// ── POST /api/order/cash-pay ──────────────────────────────
// Marks a pending cash order as paid (after staff collects cash)
router.post('/cash-pay', authenticate, async (req, res) => {
  const { order_id } = req.body;
  try {
    const orderCheck = await db.query(
      `SELECT * FROM orders
       WHERE id = $1 AND user_id = $2 AND payment_method = 'cash' AND payment_status = 'pending'`,
      [order_id, req.user.id]
    );
    if (orderCheck.rows.length === 0)
      return res.status(404).json({ error: 'Order not found or already processed' });

    const order      = orderCheck.rows[0];
    const session_id = order.session_id;

    await db.query(
      `UPDATE orders SET payment_status = 'paid', cash_code = NULL WHERE id = $1`,
      [order_id]
    );

    // Complete the session
    const cartStats = await db.query(
      `SELECT COUNT(*) as item_count, SUM(quantity * price_at_scan) as total
       FROM cart_items WHERE session_id = $1`,
      [session_id]
    );
    const stats = cartStats.rows[0];
    await db.query(
      `UPDATE sessions
       SET status='completed', exit_time=NOW(), payment_time=NOW(),
           total_amount=$1, item_count=$2,
           duration_mins=ROUND(EXTRACT(EPOCH FROM (NOW()-entry_time))/60)
       WHERE id=$3`,
      [stats.total || 0, stats.item_count || 0, session_id]
    );

    // Decrement stock
    try {
      await db.query(
        `UPDATE store_products sp
         SET stock_quantity = GREATEST(0, sp.stock_quantity - ci.quantity),
             in_stock       = (GREATEST(0, sp.stock_quantity - ci.quantity) > 0),
             is_available   = (GREATEST(0, sp.stock_quantity - ci.quantity) > 0)
         FROM cart_items ci JOIN orders o ON o.session_id = ci.session_id
         WHERE o.id=$1 AND sp.product_id=ci.product_id
           AND sp.store_id=o.store_id AND sp.stock_quantity IS NOT NULL`,
        [order_id]
      );
    } catch (e) { console.error('Stock decrement (non-fatal):', e.message); }

    return res.json({ success: true, order_id, order_number: order.order_number, amount: order.total });
  } catch (error) {
    console.error('Cash pay error:', error.message);
    return res.status(500).json({ error: 'Could not confirm cash payment' });
  }
});

// ── Auto-fail stale pending orders (Razorpay only) ────────
const cleanPendingOrders = async () => {
  try {
    await db.query(
      `UPDATE orders SET payment_status = 'failed'
       WHERE payment_status = 'pending'
         AND (payment_method IS NULL OR payment_method = 'razorpay')
         AND razorpay_payment_id IS NULL
         AND created_at < NOW() - INTERVAL '30 minutes'`
    );
    // Expire stale cash orders after 15 minutes
    await db.query(
      `UPDATE orders SET payment_status = 'cancelled', cash_code = NULL
       WHERE payment_status = 'pending'
         AND payment_method = 'cash'
         AND created_at < NOW() - INTERVAL '15 minutes'`
    );
  } catch (e) {
    console.error('Clean pending orders error:', e.message);
  }
};
setInterval(cleanPendingOrders, 15 * 60 * 1000);
cleanPendingOrders();

module.exports = router;