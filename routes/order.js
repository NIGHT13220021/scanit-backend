const express  = require('express');
const router   = express.Router();
const crypto   = require('crypto');
const Razorpay = require('razorpay');
const { createClient } = require('@supabase/supabase-js');
const { authenticate } = require('../middleware/auth');
require('dotenv').config();

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const razorpay = new Razorpay({
  key_id:     process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// ── POST /api/order/create-razorpay ─────────────────────
// Creates a Razorpay order — called before opening payment modal
router.post('/create-razorpay', authenticate, async (req, res) => {
  try {
    const { session_id, amount } = req.body;

    if (!session_id || !amount) {
      return res.status(400).json({ error: 'session_id and amount required' });
    }

    // Verify session is active
    const { data: session } = await supabase
      .from('sessions')
      .select('id, store_id, status')
      .eq('id', session_id)
      .eq('user_id', req.user.id)
      .single();

    if (!session || session.status !== 'active') {
      return res.status(400).json({ error: 'Invalid or expired session' });
    }

    // Create Razorpay order
    const order = await razorpay.orders.create({
      amount:   amount, // in paise
      currency: 'INR',
      receipt:  `oryn_${session_id}_${Date.now()}`,
    });

    return res.json({
      success:          true,
      razorpay_order_id: order.id,
      amount:           order.amount,
      currency:         order.currency,
    });

  } catch (error) {
    console.error('Create Razorpay order error:', error.message);
    return res.status(500).json({ error: 'Could not create payment order' });
  }
});

// ── POST /api/order/verify ───────────────────────────────
// Verifies Razorpay payment signature + creates order in DB
router.post('/verify', authenticate, async (req, res) => {
  try {
    const {
      session_id,
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature,
      total_amount,
      item_count,
    } = req.body;

    // ── Step 1: Verify Razorpay signature ──
    const body      = razorpay_order_id + "|" + razorpay_payment_id;
    const expected  = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(body)
      .digest('hex');

    if (expected !== razorpay_signature) {
      return res.status(400).json({ error: 'Payment verification failed — invalid signature' });
    }

    // ── Step 2: Get session + cart items ──
    const { data: session } = await supabase
      .from('sessions')
      .select('id, store_id, user_id')
      .eq('id', session_id)
      .single();

    if (!session) {
      return res.status(400).json({ error: 'Session not found' });
    }

    const { data: cartItems } = await supabase
      .from('cart_items')
      .select('id, product_id, quantity, price_at_scan')
      .eq('session_id', session_id);

    // ── Step 3: Create order in DB ──
    const { data: order, error: orderError } = await supabase
      .from('orders')
      .insert({
        session_id:          session_id,
        store_id:            session.store_id,
        user_id:             req.user.id,
        total:               total_amount,
        payment_status:      'paid',
        payment_method:      'online',
        razorpay_order_id:   razorpay_order_id,
        razorpay_payment_id: razorpay_payment_id,
      })
      .select()
      .single();

    if (orderError) throw orderError;

    // ── Step 4: Create order items ──
    if (cartItems && cartItems.length > 0) {
      const orderItems = cartItems.map(item => ({
        order_id:   order.id,
        product_id: item.product_id,
        quantity:   item.quantity,
        price:      item.price_at_scan,
      }));

      await supabase.from('order_items').insert(orderItems);
    }

    // ── Step 5: Mark session completed ──
    await supabase
      .from('sessions')
      .update({
        status:        'completed',
        exit_time:     new Date().toISOString(),
        payment_time:  new Date().toISOString(),
        total_amount:  total_amount,
        item_count:    item_count || cartItems?.length || 0,
        duration_mins: null, // calculated by trigger
      })
      .eq('id', session_id);

    // ── Step 6: Generate exit QR value ──
    const exitQRValue = `ORYN-EXIT-${order.id}-${Date.now()}`;

    // Save exit QR to order
    await supabase
      .from('orders')
      .update({ exit_qr_code: exitQRValue })
      .eq('id', order.id);

    return res.json({
      success:  true,
      order:    { ...order, exit_qr_code: exitQRValue },
      exit_qr:  exitQRValue,
    });

  } catch (error) {
    console.error('Verify payment error:', error.message);
    return res.status(500).json({ error: 'Payment verification failed' });
  }
});

// ── GET /api/order/history ───────────────────────────────
// Customer's order history
router.get('/history', authenticate, async (req, res) => {
  try {
    const { data: orders, error } = await supabase
      .from('orders')
      .select(`
        id, total, payment_status, payment_method,
        razorpay_payment_id, created_at,
        stores(name, city),
        order_items(quantity, price, products(name, barcode))
      `)
      .eq('user_id', req.user.id)
      .eq('payment_status', 'paid')
      .order('created_at', { ascending: false });

    if (error) throw error;

    const enriched = (orders || []).map(o => ({
      id:             o.id,
      total:          o.total,
      payment_status: o.payment_status,
      payment_id:     o.razorpay_payment_id,
      date:           o.created_at,
      store_name:     o.stores?.name || 'Store',
      store_city:     o.stores?.city || '',
      items: (o.order_items || []).map(i => ({
        name:     i.products?.name || 'Unknown',
        quantity: i.quantity,
        price:    i.price,
      })),
    }));

    return res.json({ success: true, orders: enriched });

  } catch (error) {
    console.error('Order history error:', error.message);
    return res.status(500).json({ error: 'Could not fetch orders' });
  }
});

// ── GET /api/order/:id/receipt ───────────────────────────
// Single order receipt
router.get('/:id/receipt', authenticate, async (req, res) => {
  try {
    const { data: order, error } = await supabase
      .from('orders')
      .select(`
        id, total, payment_status, razorpay_payment_id, 
        razorpay_order_id, exit_qr_code, created_at,
        stores(name, address, city),
        order_items(quantity, price, products(name, barcode, brand))
      `)
      .eq('id', req.params.id)
      .eq('user_id', req.user.id)
      .single();

    if (error || !order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    return res.json({ success: true, order });

  } catch (error) {
    console.error('Receipt error:', error.message);
    return res.status(500).json({ error: 'Could not fetch receipt' });
  }
});

module.exports = router;