const express    = require('express');
const router     = express.Router();
const { createClient } = require('@supabase/supabase-js');
const jwt        = require('jsonwebtoken');
const QRCode     = require('qrcode');
const bcrypt     = require('bcryptjs');
require('dotenv').config();

const axios = require('axios');

const otpStore = new Map();

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ════════════════════════════════════════════════════════
// MIDDLEWARE
// ════════════════════════════════════════════════════════

const authAdmin = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer '))
      return res.status(401).json({ error: 'No token. Please login.' });
    const token   = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!['store_owner', 'super_admin'].includes(decoded.role))
      return res.status(403).json({ error: 'Access denied.' });
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
};

const authSuperAdmin = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer '))
      return res.status(401).json({ error: 'No token.' });
    const token   = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'super_admin')
      return res.status(403).json({ error: 'Super admin access only.' });
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
};

// ════════════════════════════════════════════════════════
// AUTH — LOGIN
// ════════════════════════════════════════════════════════

router.post('/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password)
      return res.status(400).json({ error: 'Phone and password required.' });

    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('phone', phone)
      .in('role', ['store_owner', 'super_admin'])
      .single();

    if (error || !user)
      return res.status(401).json({ error: 'Invalid credentials.' });

    const isValid = await bcrypt.compare(password, user.admin_password);
    if (!isValid)
      return res.status(401).json({ error: 'Invalid credentials.' });

    let store = null;
    if (user.role === 'store_owner' && user.store_id) {
      const { data: storeData } = await supabase
        .from('stores')
        .select('id, name, address')
        .eq('id', user.store_id)
        .single();
      store = storeData;
    }

    const { data: freshUser } = await supabase
      .from('users')
      .select('id, phone, role, store_id')
      .eq('id', user.id)
      .single();

    const token = jwt.sign(
      {
        id:       freshUser.id,
        phone:    freshUser.phone,
        role:     freshUser.role,
        store_id: freshUser.store_id || null,
      },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.json({ success: true, token, role: user.role, phone: user.phone, store });

  } catch (error) {
    console.error('Admin login error:', error.message);
    return res.status(500).json({ error: 'Login failed.' });
  }
});

// ════════════════════════════════════════════════════════
// AUTH — FORGOT PASSWORD
// ════════════════════════════════════════════════════════

router.post('/forgot-password', async (req, res) => {
  try {
    const { phone } = req.body;

    if (!phone)
      return res.status(400).json({ error: 'Phone number required.' });

    const { data: user, error } = await supabase
      .from('users')
      .select('id, phone, role')
      .eq('phone', phone)
      .in('role', ['store_owner', 'super_admin'])
      .single();

    if (error || !user) {
      return res.json({ success: true, message: 'If this number is registered, an OTP has been sent.' });
    }

    const otp       = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000;

    otpStore.set(phone, { otp, expiresAt, userId: user.id, verified: false });

    const apiKey         = process.env.TWOFACTOR_API_KEY;
    const formattedPhone = `91${phone}`;
    const smsUrl         = `https://2factor.in/API/V1/${apiKey}/SMS/${formattedPhone}/${otp}/AUTOGEN`;

    const smsRes  = await axios.get(smsUrl);
    const smsData = smsRes.data;

    if (smsData.Status !== 'Success') {
      console.error('2Factor SMS OTP error:', smsData);
      return res.status(500).json({ error: 'Failed to send OTP. Please try again.' });
    }

    console.log(`[DEV] OTP for ${phone}: ${otp}`);
    return res.json({ success: true, message: 'OTP sent successfully.' });

  } catch (error) {
    console.error('Forgot password error:', error.message);
    return res.status(500).json({ error: 'Failed to send OTP.' });
  }
});

// ════════════════════════════════════════════════════════
// STORE OWNER — STATS
// ════════════════════════════════════════════════════════

router.get('/stats', authAdmin, async (req, res) => {
  try {
    const store_id       = req.user.store_id;
    const todayStart     = new Date(); todayStart.setHours(0, 0, 0, 0);
    const monthStart     = new Date(); monthStart.setDate(1); monthStart.setHours(0, 0, 0, 0);
    const yesterdayStart = new Date(); yesterdayStart.setDate(yesterdayStart.getDate() - 1); yesterdayStart.setHours(0, 0, 0, 0);
    const yesterdayEnd   = new Date(); yesterdayEnd.setHours(0, 0, 0, 0);

    const [
      { data: todayOrders },
      { data: monthOrders },
      { data: liveSessions },
      { count: productCount },
      { count: todayOrderCount },
      { data: yesterdayOrders },
      { count: pendingOrderCount },
      { count: lowStockCount },
      { data: allSessions },
      { data: abandonedSessions },
      { data: allOrderUsers },
    ] = await Promise.all([
      supabase.from('orders').select('total').eq('store_id', store_id).eq('payment_status', 'paid').gte('created_at', todayStart.toISOString()),
      supabase.from('orders').select('total').eq('store_id', store_id).eq('payment_status', 'paid').gte('created_at', monthStart.toISOString()),
      supabase.from('sessions').select('id').eq('store_id', store_id).eq('status', 'active'),
      supabase.from('store_products').select('id', { count: 'exact' }).eq('store_id', store_id).eq('is_available', true),
      supabase.from('orders').select('id', { count: 'exact' }).eq('store_id', store_id).gte('created_at', todayStart.toISOString()),
      supabase.from('orders').select('total').eq('store_id', store_id).eq('payment_status', 'paid')
        .gte('created_at', yesterdayStart.toISOString())
        .lt('created_at', yesterdayEnd.toISOString()),
      supabase.from('orders').select('id', { count: 'exact' }).eq('store_id', store_id).eq('payment_status', 'pending'),
      supabase.from('store_products').select('id', { count: 'exact' }).eq('store_id', store_id).eq('in_stock', false),
      supabase.from('sessions').select('id').eq('store_id', store_id).gte('entry_time', todayStart.toISOString()),
      supabase.from('sessions').select('id').eq('store_id', store_id).eq('status', 'active')
        .gte('entry_time', new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString()),
      supabase.from('orders').select('user_id').eq('store_id', store_id).eq('payment_status', 'paid'),
    ]);

    const todayRevenue     = todayOrders?.reduce((s, o) => s + (o.total || 0), 0) || 0;
    const yesterdayRevenue = yesterdayOrders?.reduce((s, o) => s + (o.total || 0), 0) || 0;

    const totalSessionsToday    = allSessions?.length || 0;
    const activeHangingSessions = abandonedSessions?.length || 0;
    const cartAbandonmentRate   = totalSessionsToday > 0 ? activeHangingSessions / totalSessionsToday : 0;

    const userOrderMap = {};
    (allOrderUsers || []).forEach(o => {
      userOrderMap[o.user_id] = (userOrderMap[o.user_id] || 0) + 1;
    });
    const totalUniqueCustomers = Object.keys(userOrderMap).length;
    const repeatCustomerCount  = Object.values(userOrderMap).filter(c => c > 1).length;
    const repeatCustomerRate   = totalUniqueCustomers > 0 ? repeatCustomerCount / totalUniqueCustomers : 0;
    const conversionRate       = totalSessionsToday > 0 ? Math.min((todayOrderCount || 0) / totalSessionsToday, 1) : 0.3;

    return res.json({
      today_revenue:         todayRevenue,
      month_revenue:         monthOrders?.reduce((s, o) => s + (o.total || 0), 0) || 0,
      today_orders:          todayOrderCount || 0,
      live_sessions:         liveSessions?.length || 0,
      product_count:         productCount || 0,
      yesterday_revenue:     yesterdayRevenue,
      pending_orders:        pendingOrderCount || 0,
      low_stock_count:       lowStockCount || 0,
      cart_abandonment_rate: cartAbandonmentRate,
      conversion_rate:       conversionRate,
      repeat_customer_rate:  repeatCustomerRate,
      daily_target:          20,
    });

  } catch (error) {
    console.error('Stats error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch stats.' });
  }
});

// ════════════════════════════════════════════════════════
// ORDERS
// ════════════════════════════════════════════════════════

router.get('/orders', authAdmin, async (req, res) => {
  try {
    const store_id = req.user.store_id;
    const { status, page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;

    let query = supabase
      .from('orders')
      .select('id, total, payment_status, razorpay_payment_id, created_at, users(phone)')
      .order('created_at', { ascending: false })
      .range(offset, offset + Number(limit) - 1);

    if (req.user.role === 'store_owner') query = query.eq('store_id', store_id);
    if (status && status !== 'all')      query = query.eq('payment_status', status);

    const { data: orders, error } = await query;
    if (error) throw error;

    return res.json({ success: true, orders: orders || [] });

  } catch (error) {
    console.error('Orders error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch orders.' });
  }
});

// ════════════════════════════════════════════════════════
// LIVE SESSIONS
// ════════════════════════════════════════════════════════

router.get('/sessions/live', authAdmin, async (req, res) => {
  try {
    const store_id = req.user.store_id;

    const { data: sessions, error } = await supabase
      .from('sessions')
      .select('id, entry_time, user_id, users(phone)')
      .eq('store_id', store_id)
      .eq('status', 'active')
      .order('entry_time', { ascending: false });

    if (error) throw error;
    if (!sessions || sessions.length === 0)
      return res.json({ success: true, sessions: [] });

    const enriched = await Promise.all(sessions.map(async s => {
      const { data: cartItems } = await supabase
        .from('cart_items')
        .select('id, quantity, price_at_scan, products(name)')
        .eq('session_id', s.id);

      const items = cartItems || [];
      const total = items.reduce((sum, i) =>
        sum + ((i.quantity || 0) * (parseFloat(i.price_at_scan) || 0)), 0);

      return {
        session_id:  s.id,
        phone:       s.users?.phone || 'Unknown',
        item_count:  items.length,
        cart_total:  total,
        minutes_ago: Math.floor((Date.now() - new Date(s.entry_time).getTime()) / 60000),
        cart: items.map(i => ({
          name:     i.products?.name || 'Unknown',
          quantity: i.quantity,
          price:    parseFloat(i.price_at_scan) || 0,
        })),
      };
    }));

    return res.json({ success: true, sessions: enriched });

  } catch (error) {
    console.error('Live sessions error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch live sessions.' });
  }
});

// ════════════════════════════════════════════════════════
// PRODUCTS
// ════════════════════════════════════════════════════════

router.get('/products', authAdmin, async (req, res) => {
  try {
    const { data: products, error } = await supabase
      .from('store_products')
      .select(`id, price, mrp, gst_percent, in_stock, is_available, products(id, name, barcode, brand, category)`)
      .eq('store_id', req.user.store_id)
      .order('updated_at', { ascending: false });

    if (error) throw error;

    const flat = (products || []).map(sp => ({
      store_product_id: sp.id,
      product_id:   sp.products?.id,
      name:         sp.products?.name,
      barcode:      sp.products?.barcode,
      brand:        sp.products?.brand,
      category:     sp.products?.category,
      price:        sp.price,
      mrp:          sp.mrp,
      gst_percent:  sp.gst_percent,
      in_stock:     sp.in_stock,
      is_available: sp.is_available,
    }));

    return res.json({ success: true, products: flat });

  } catch (error) {
    console.error('Products error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch products.' });
  }
});

// ────────────────────────────────────────────────────────
// POST /products  — Add product
// ────────────────────────────────────────────────────────

router.post('/products', authAdmin, async (req, res) => {
  try {
    const store_id = req.user.store_id;
    let { barcode, name, brand, category, price, mrp, gst_percent } = req.body;

    if (!barcode || !name || !price)
      return res.status(400).json({ error: 'Barcode, name and price are required.' });

    price = parseFloat(String(price).replace(/[^\d.]/g, ''));
    mrp   = parseFloat(String(mrp || price).replace(/[^\d.]/g, ''));

    if (isNaN(price) || price <= 0)
      return res.status(400).json({ error: 'Price must be a valid number greater than 0.' });

    // Step 1: upsert into products table
    const { data: product, error: prodError } = await supabase
      .from('products')
      .upsert(
        { barcode, name, brand: brand || null, category: category || null },
        { onConflict: 'barcode' }
      )
      .select()
      .single();

    if (prodError) {
      console.error('products upsert error:', prodError);
      throw prodError;
    }

    // Step 2: upsert into store_products
    // in_stock=true + is_available=true so scanner finds product immediately
    const { data: storeProduct, error: spError } = await supabase
      .from('store_products')
      .upsert(
        {
          store_id,
          product_id:   product.id,
          price,
          mrp,
          gst_percent:  parseFloat(gst_percent) || 0,
          in_stock:     true,
          is_available: true,
        },
        { onConflict: 'store_id,product_id' }
      )
      .select()
      .single();

    if (spError) {
      console.error('store_products upsert error:', spError);
      throw spError;
    }

    return res.json({
      success: true,
      message: 'Product added successfully.',
      product: {
        store_product_id: storeProduct.id,
        product_id:   product.id,
        barcode:      product.barcode,
        name:         product.name,
        brand:        product.brand,
        category:     product.category,
        price:        storeProduct.price,
        mrp:          storeProduct.mrp,
        gst_percent:  storeProduct.gst_percent,
        in_stock:     storeProduct.in_stock,
        is_available: storeProduct.is_available,
      }
    });

  } catch (error) {
    console.error('Add product error:', error.message);
    return res.status(500).json({ error: 'Failed to add product.' });
  }
});

// ────────────────────────────────────────────────────────
// PUT /products/:id  — Edit product
// ────────────────────────────────────────────────────────

router.put('/products/:id', authAdmin, async (req, res) => {
  try {
    const { id }   = req.params;
    const store_id = req.user.store_id;
    let { name, brand, category, price, mrp, gst_percent, in_stock, is_available } = req.body;

    price = parseFloat(String(price).replace(/[^\d.]/g, ''));
    mrp   = parseFloat(String(mrp || price).replace(/[^\d.]/g, ''));

    if (isNaN(price) || price <= 0)
      return res.status(400).json({ error: 'Price must be greater than 0.' });

    const stockStatus = typeof in_stock === 'boolean' ? in_stock : true;
    const availStatus = typeof is_available === 'boolean' ? is_available : stockStatus;

    // NOTE: do NOT set updated_at manually — column has DEFAULT now()
    const { error } = await supabase
      .from('store_products')
      .update({
        price,
        mrp,
        gst_percent:  parseFloat(gst_percent) || 0,
        in_stock:     stockStatus,
        is_available: availStatus,
      })
      .eq('id', id)
      .eq('store_id', store_id);

    if (error) throw error;

    if (name || brand || category) {
      const { data: sp } = await supabase
        .from('store_products').select('product_id').eq('id', id).single();
      if (sp) {
        await supabase.from('products')
          .update({ name, brand, category }).eq('id', sp.product_id);
      }
    }

    return res.json({ success: true, message: 'Product updated.' });

  } catch (error) {
    console.error('Update product error:', error.message);
    return res.status(500).json({ error: 'Failed to update product.' });
  }
});

// ────────────────────────────────────────────────────────
// DELETE /products/:id
// ────────────────────────────────────────────────────────

router.delete('/products/:id', authAdmin, async (req, res) => {
  try {
    const { error } = await supabase
      .from('store_products')
      .delete()
      .eq('id', req.params.id)
      .eq('store_id', req.user.store_id);

    if (error) throw error;
    return res.json({ success: true, message: 'Product removed from store.' });

  } catch (error) {
    console.error('Delete product error:', error.message);
    return res.status(500).json({ error: 'Failed to remove product.' });
  }
});

// ────────────────────────────────────────────────────────
// PATCH /products/:id/stock  — Toggle stock on/off
// ────────────────────────────────────────────────────────

router.patch('/products/:id/stock', authAdmin, async (req, res) => {
  try {
    const { id }       = req.params;
    const { in_stock } = req.body;

    if (typeof in_stock !== 'boolean')
      return res.status(400).json({ error: 'in_stock must be true or false.' });

    const { error } = await supabase
      .from('store_products')
      .update({ in_stock, is_available: in_stock })
      .eq('id', id)
      .eq('store_id', req.user.store_id);

    if (error) throw error;

    return res.json({
      success: true,
      message: `Product marked ${in_stock ? 'in stock' : 'out of stock'}.`,
    });

  } catch (error) {
    console.error('Stock toggle error:', error.message);
    return res.status(500).json({ error: 'Failed to update stock status.' });
  }
});

// ────────────────────────────────────────────────────────
// POST /products/bulk  — Bulk import from CSV
// ────────────────────────────────────────────────────────

router.post('/products/bulk', authAdmin, async (req, res) => {
  try {
    const store_id     = req.user.store_id;
    const { products } = req.body;

    if (!Array.isArray(products) || products.length === 0)
      return res.status(400).json({ error: 'products array is required.' });

    const results = { success: [], failed: [] };

    for (const item of products) {
      try {
        let { barcode, name, brand, category, price, mrp, gst_percent } = item;

        if (!barcode || !name || !price) {
          results.failed.push({ barcode, reason: 'Missing barcode, name or price.' });
          continue;
        }

        price = parseFloat(String(price).replace(/[^\d.]/g, ''));
        mrp   = parseFloat(String(mrp || price).replace(/[^\d.]/g, ''));

        if (isNaN(price) || price <= 0) {
          results.failed.push({ barcode, reason: 'Invalid price.' });
          continue;
        }

        const { data: product, error: prodError } = await supabase
          .from('products')
          .upsert(
            { barcode, name, brand: brand || null, category: category || null },
            { onConflict: 'barcode' }
          )
          .select()
          .single();

        if (prodError) throw prodError;

        const { error: spError } = await supabase
          .from('store_products')
          .upsert(
            {
              store_id,
              product_id:   product.id,
              price,
              mrp,
              gst_percent:  parseFloat(gst_percent) || 0,
              in_stock:     true,
              is_available: true,
            },
            { onConflict: 'store_id,product_id' }
          );

        if (spError) throw spError;

        results.success.push({ barcode, name });

      } catch (err) {
        results.failed.push({ barcode: item.barcode, reason: err.message });
      }
    }

    return res.json({
      success:  true,
      message:  `${results.success.length} products imported, ${results.failed.length} failed.`,
      imported: results.success,
      failed:   results.failed,
    });

  } catch (error) {
    console.error('Bulk import error:', error.message);
    return res.status(500).json({ error: 'Bulk import failed.' });
  }
});

// ════════════════════════════════════════════════════════
// STORE QR + SETTINGS
// ════════════════════════════════════════════════════════

router.get('/store/qr', authAdmin, async (req, res) => {
  try {
    const { data: store, error } = await supabase
      .from('stores').select('name, entry_qr_code').eq('id', req.user.store_id).single();

    if (error || !store) return res.status(404).json({ error: 'Store not found.' });

    const qrImage = await QRCode.toDataURL(store.entry_qr_code, {
      width: 400, margin: 2, color: { dark: '#000000', light: '#ffffff' },
    });

    return res.json({ success: true, qr_image: qrImage, qr_code_value: store.entry_qr_code, store_name: store.name });

  } catch (error) {
    console.error('Store QR error:', error.message);
    return res.status(500).json({ error: 'Failed to generate QR code.' });
  }
});

router.post('/store/qr/regenerate', authAdmin, async (req, res) => {
  try {
    const store_id = req.user.store_id;

    const { data: store, error: storeError } = await supabase
      .from('stores').select('name').eq('id', store_id).single();

    if (storeError || !store)
      return res.status(404).json({ error: 'Store not found.' });

    const newQRValue = `NIVO_${store.name.replace(/\s+/g, '_').toUpperCase()}_${Date.now()}`;

    const { error: updateError } = await supabase
      .from('stores').update({ entry_qr_code: newQRValue }).eq('id', store_id);

    if (updateError) throw updateError;

    const qrImage = await QRCode.toDataURL(newQRValue, {
      width: 400, margin: 2, color: { dark: '#000000', light: '#ffffff' },
    });

    return res.json({ success: true, qr_image: qrImage, qr_code_value: newQRValue, store_name: store.name });

  } catch (error) {
    console.error('Regenerate QR error:', error.message);
    return res.status(500).json({ error: 'Failed to regenerate QR code.' });
  }
});

router.get('/store', authAdmin, async (req, res) => {
  try {
    const { data: store, error } = await supabase
      .from('stores').select('*').eq('id', req.user.store_id).single();
    if (error) throw error;
    return res.json({ success: true, store });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch store settings.' });
  }
});

router.put('/store', authAdmin, async (req, res) => {
  try {
    const { name, address, phone } = req.body;
    const { error } = await supabase
      .from('stores').update({ name, address, phone }).eq('id', req.user.store_id);
    if (error) throw error;
    return res.json({ success: true, message: 'Store updated.' });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to update store.' });
  }
});

// ════════════════════════════════════════════════════════
// CHANGE PASSWORD
// ════════════════════════════════════════════════════════

router.put('/change-password', authAdmin, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword)
      return res.status(400).json({ error: 'Current and new password required.' });

    if (newPassword.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters.' });

    const { data: user, error } = await supabase
      .from('users').select('id, admin_password').eq('id', req.user.id).single();

    if (error || !user)
      return res.status(404).json({ error: 'User not found.' });

    const isValid = await bcrypt.compare(currentPassword, user.admin_password);
    if (!isValid)
      return res.status(401).json({ error: 'Current password is incorrect.' });

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    const { error: updateError } = await supabase
      .from('users').update({ admin_password: hashedPassword }).eq('id', req.user.id);

    if (updateError) throw updateError;

    return res.json({ success: true, message: 'Password changed successfully.' });

  } catch (error) {
    console.error('Change password error:', error.message);
    return res.status(500).json({ error: 'Failed to change password.' });
  }
});

// ════════════════════════════════════════════════════════
// ANALYTICS
// ════════════════════════════════════════════════════════

router.get('/analytics', authAdmin, async (req, res) => {
  try {
    const store_id = req.user.store_id;

    const { data: orders } = await supabase
      .from('orders').select('total, created_at')
      .eq('store_id', store_id).eq('payment_status', 'paid')
      .gte('created_at', new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString());

    const revenueByDay = {};
    (orders || []).forEach(o => {
      const day = new Date(o.created_at).toLocaleDateString('en-IN', { day: '2-digit', month: 'short' });
      revenueByDay[day] = (revenueByDay[day] || 0) + (o.total || 0);
    });

    const { data: topItems } = await supabase
      .from('order_items')
      .select('quantity, store_products(price, products(name)), orders!inner(store_id, payment_status)')
      .eq('orders.store_id', store_id)
      .eq('orders.payment_status', 'paid');

    const productMap = {};
    (topItems || []).forEach(item => {
      const name = item.store_products?.products?.name || 'Unknown';
      if (!productMap[name]) productMap[name] = { name, units: 0, revenue: 0 };
      productMap[name].units   += item.quantity;
      productMap[name].revenue += item.quantity * (item.store_products?.price || 0);
    });

    const topProducts = Object.values(productMap).sort((a, b) => b.units - a.units).slice(0, 5);

    const { data: storeProducts } = await supabase
      .from('store_products')
      .select('id, in_stock, price, products(id, name)')
      .eq('store_id', store_id)
      .eq('in_stock', true);

    const { data: allSoldItems } = await supabase
      .from('order_items')
      .select('store_product_id, orders!inner(store_id, payment_status, created_at)')
      .eq('orders.store_id', store_id)
      .eq('orders.payment_status', 'paid')
      .order('orders(created_at)', { ascending: false });

    const lastSoldMap = {};
    (allSoldItems || []).forEach(item => {
      if (!lastSoldMap[item.store_product_id])
        lastSoldMap[item.store_product_id] = item.orders?.created_at;
    });

    const allProductsWithAge = (storeProducts || []).map(sp => {
      const lastSold  = lastSoldMap[sp.id];
      const daysSince = lastSold
        ? Math.floor((Date.now() - new Date(lastSold).getTime()) / (1000 * 60 * 60 * 24))
        : 999;
      return {
        id:                   sp.id,
        name:                 sp.products?.name || 'Unknown',
        stock:                sp.in_stock ? 1 : 0,
        price:                sp.price || 0,
        days_since_last_sale: daysSince,
      };
    });

    const deadStock = allProductsWithAge
      .filter(p => p.days_since_last_sale >= 21)
      .sort((a, b) => b.days_since_last_sale - a.days_since_last_sale)
      .slice(0, 5)
      .map(p => ({
        name:        p.name,
        days_idle:   p.days_since_last_sale === 999 ? 'Never sold' : p.days_since_last_sale,
        stock_value: p.price,
      }));

    const monthStart = new Date(); monthStart.setDate(1); monthStart.setHours(0, 0, 0, 0);
    const { data: monthItems } = await supabase
      .from('order_items')
      .select('quantity, store_products(price, products(name)), orders!inner(store_id, payment_status, created_at)')
      .eq('orders.store_id', store_id)
      .eq('orders.payment_status', 'paid')
      .gte('orders.created_at', monthStart.toISOString());

    const starMap = {};
    (monthItems || []).forEach(item => {
      const name = item.store_products?.products?.name || 'Unknown';
      if (!starMap[name]) starMap[name] = { name, units_sold: 0, revenue: 0 };
      starMap[name].units_sold += item.quantity;
      starMap[name].revenue   += item.quantity * (item.store_products?.price || 0);
    });

    const daysIntoMonth = new Date().getDate();
    const starProducts  = Object.values(starMap)
      .sort((a, b) => b.units_sold - a.units_sold)
      .slice(0, 3)
      .map(p => ({
        ...p,
        velocity: parseFloat((p.units_sold / Math.max(daysIntoMonth, 1)).toFixed(2)),
      }));

    const now           = new Date();
    const weekStart     = new Date(now); weekStart.setDate(now.getDate() - 7);      weekStart.setHours(0, 0, 0, 0);
    const prevWeekStart = new Date(now); prevWeekStart.setDate(now.getDate() - 14); prevWeekStart.setHours(0, 0, 0, 0);

    const [
      { data: thisWeekOrders },
      { data: lastWeekOrders },
      { data: thisWeekNewUsers },
    ] = await Promise.all([
      supabase.from('orders').select('total, created_at, user_id')
        .eq('store_id', store_id).eq('payment_status', 'paid')
        .gte('created_at', weekStart.toISOString()),
      supabase.from('orders').select('total, user_id')
        .eq('store_id', store_id).eq('payment_status', 'paid')
        .gte('created_at', prevWeekStart.toISOString())
        .lt('created_at', weekStart.toISOString()),
      supabase.from('users').select('id')
        .eq('role', 'customer')
        .gte('created_at', weekStart.toISOString()),
    ]);

    const thisWeekRevenue    = (thisWeekOrders || []).reduce((s, o) => s + (o.total || 0), 0);
    const lastWeekRevenue    = (lastWeekOrders || []).reduce((s, o) => s + (o.total || 0), 0);
    const thisWeekOrderCount = thisWeekOrders?.length || 0;
    const lastWeekOrderCount = lastWeekOrders?.length || 0;
    const avgOrderValue      = thisWeekOrderCount > 0 ? thisWeekRevenue / thisWeekOrderCount : 0;

    const dayRevMap = {};
    (thisWeekOrders || []).forEach(o => {
      const dayName = new Date(o.created_at).toLocaleDateString('en-IN', { weekday: 'long' });
      dayRevMap[dayName] = (dayRevMap[dayName] || 0) + (o.total || 0);
    });
    const bestDayEntry = Object.entries(dayRevMap).sort((a, b) => b[1] - a[1])[0];

    let aiInsight = "Keep your top products stocked — they're driving consistent growth.";
    if (thisWeekRevenue > lastWeekRevenue * 1.2)
      aiInsight = "Great week! Revenue is up 20%+. Identify what drove this and repeat it next week.";
    else if (thisWeekRevenue < lastWeekRevenue * 0.8)
      aiInsight = "Revenue dipped this week. Check if any top products went out of stock.";
    else if (thisWeekOrderCount > lastWeekOrderCount)
      aiInsight = "More orders this week. Focus on upselling to increase average order value.";

    const weeklySummary = {
      week_label:        weekStart.toLocaleDateString('en-IN', { day: 'numeric', month: 'short' }),
      this_week_revenue: thisWeekRevenue,
      last_week_revenue: lastWeekRevenue,
      this_week_orders:  thisWeekOrderCount,
      last_week_orders:  lastWeekOrderCount,
      avg_order_value:   parseFloat(avgOrderValue.toFixed(2)),
      prev_avg_order:    lastWeekOrderCount > 0
        ? parseFloat(((lastWeekOrders || []).reduce((s, o) => s + (o.total || 0), 0) / lastWeekOrderCount).toFixed(2))
        : 0,
      new_customers:    thisWeekNewUsers?.length || 0,
      best_day:         bestDayEntry?.[0] || null,
      best_day_revenue: bestDayEntry?.[1] || 0,
      ai_insight:       aiInsight,
    };

    return res.json({
      success:        true,
      revenue_chart:  Object.entries(revenueByDay).map(([day, rev]) => ({ day, rev })),
      top_products:   topProducts,
      all_products:   allProductsWithAge,
      dead_stock:     deadStock,
      star_products:  starProducts,
      weekly_summary: weeklySummary,
    });

  } catch (error) {
    console.error('Analytics error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch analytics.' });
  }
});

// ════════════════════════════════════════════════════════
// CSV EXPORTS
// ════════════════════════════════════════════════════════

function toCSV(rows, columns) {
  if (!rows || rows.length === 0) return columns.join(',') + '\n';
  const header = columns.join(',');
  const body = rows.map(row =>
    columns.map(col => {
      const val = row[col] === null || row[col] === undefined ? '' : String(row[col]);
      return val.includes(',') || val.includes('"') || val.includes('\n')
        ? `"${val.replace(/"/g, '""')}"` : val;
    }).join(',')
  ).join('\n');
  return header + '\n' + body;
}

router.get('/export/orders', authAdmin, async (req, res) => {
  try {
    const { from, to, status } = req.query;

    let query = supabase
      .from('orders')
      .select('id, total, payment_status, razorpay_payment_id, created_at, users(phone)')
      .order('created_at', { ascending: false });

    if (req.user.role === 'store_owner') query = query.eq('store_id', req.user.store_id);
    if (status && status !== 'all')      query = query.eq('payment_status', status);
    if (from) query = query.gte('created_at', new Date(from).toISOString());
    if (to)   query = query.lte('created_at', new Date(to).toISOString());

    const { data: orders, error } = await query;
    if (error) throw error;

    const rows = (orders || []).map(o => ({
      order_id:       o.id,
      customer_phone: o.users?.phone || '—',
      amount:         o.total || 0,
      status:         o.payment_status,
      payment_id:     o.razorpay_payment_id || '—',
      date:           new Date(o.created_at).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }),
    }));

    const csv = toCSV(rows, ['order_id','customer_phone','amount','status','payment_id','date']);
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="orders_${new Date().toISOString().slice(0,10)}.csv"`);
    return res.send(csv);

  } catch (error) {
    console.error('Export orders error:', error.message);
    return res.status(500).json({ error: 'Failed to export orders.' });
  }
});

router.get('/export/products', authAdmin, async (req, res) => {
  try {
    const { data: products, error } = await supabase
      .from('store_products')
      .select('id, price, mrp, gst_percent, in_stock, is_available, products(name, barcode, brand, category)')
      .eq('store_id', req.user.store_id)
      .order('updated_at', { ascending: false });

    if (error) throw error;

    const rows = (products || []).map(sp => ({
      barcode:      sp.products?.barcode  || '—',
      name:         sp.products?.name     || '—',
      brand:        sp.products?.brand    || '—',
      category:     sp.products?.category || '—',
      price:        sp.price       || 0,
      mrp:          sp.mrp         || 0,
      gst_percent:  sp.gst_percent || 0,
      in_stock:     sp.in_stock     ? 'Yes' : 'No',
      is_available: sp.is_available ? 'Yes' : 'No',
    }));

    const csv = toCSV(rows, ['barcode','name','brand','category','price','mrp','gst_percent','in_stock','is_available']);
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="products_${new Date().toISOString().slice(0,10)}.csv"`);
    return res.send(csv);

  } catch (error) {
    console.error('Export products error:', error.message);
    return res.status(500).json({ error: 'Failed to export products.' });
  }
});

router.get('/export/revenue', authAdmin, async (req, res) => {
  try {
    const { data: orders, error } = await supabase
      .from('orders').select('total, payment_status, created_at')
      .eq('store_id', req.user.store_id)
      .order('created_at', { ascending: true });

    if (error) throw error;

    const byDay = {};
    (orders || []).forEach(o => {
      const day = new Date(o.created_at).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' });
      if (!byDay[day]) byDay[day] = { date: day, total_orders: 0, paid_orders: 0, failed_orders: 0, revenue: 0 };
      byDay[day].total_orders++;
      if (o.payment_status === 'paid')   { byDay[day].paid_orders++;   byDay[day].revenue += o.total || 0; }
      if (o.payment_status === 'failed')   byDay[day].failed_orders++;
    });

    const rows = Object.values(byDay).map(d => ({
      date:          d.date,
      total_orders:  d.total_orders,
      paid_orders:   d.paid_orders,
      failed_orders: d.failed_orders,
      revenue:       d.revenue.toFixed(2),
      avg_order:     d.paid_orders > 0 ? (d.revenue / d.paid_orders).toFixed(2) : '0.00',
    }));

    const csv = toCSV(rows, ['date','total_orders','paid_orders','failed_orders','revenue','avg_order']);
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="revenue_${new Date().toISOString().slice(0,10)}.csv"`);
    return res.send(csv);

  } catch (error) {
    console.error('Export revenue error:', error.message);
    return res.status(500).json({ error: 'Failed to export revenue.' });
  }
});

// ════════════════════════════════════════════════════════
// USERS
// ════════════════════════════════════════════════════════

router.get('/users', authAdmin, async (req, res) => {
  try {
    const { data: users, error } = await supabase
      .from('users').select('id, phone, role, created_at')
      .eq('role', 'customer').order('created_at', { ascending: false });
    if (error) throw error;
    return res.json({ success: true, users: users || [] });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch users.' });
  }
});

// ════════════════════════════════════════════════════════
// SUPER ADMIN
// ════════════════════════════════════════════════════════

router.get('/superadmin/stats', authSuperAdmin, async (req, res) => {
  try {
    const [
      { count: storeCount },
      { count: userCount },
      { count: orderCount },
      { data: revenue },
    ] = await Promise.all([
      supabase.from('stores').select('id', { count: 'exact' }).eq('is_active', true),
      supabase.from('users').select('id', { count: 'exact' }).eq('role', 'customer'),
      supabase.from('orders').select('id', { count: 'exact' }),
      supabase.from('orders').select('total').eq('payment_status', 'paid'),
    ]);

    return res.json({
      success:       true,
      store_count:   storeCount || 0,
      user_count:    userCount  || 0,
      order_count:   orderCount || 0,
      total_revenue: (revenue || []).reduce((s, o) => s + (o.total || 0), 0),
    });

  } catch (error) {
    console.error('SA stats error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch platform stats.' });
  }
});

router.get('/superadmin/stores', authSuperAdmin, async (req, res) => {
  try {
    const { data: stores, error } = await supabase
      .from('stores').select('*').order('created_at', { ascending: false });
    if (error) throw error;

    const enriched = await Promise.all((stores || []).map(async store => {
      const { data: orders } = await supabase
        .from('orders').select('total').eq('store_id', store.id).eq('payment_status', 'paid');
      return {
        ...store,
        order_count:   orders?.length || 0,
        total_revenue: (orders || []).reduce((s, o) => s + (o.total || 0), 0),
      };
    }));

    return res.json({ success: true, stores: enriched });

  } catch (error) {
    console.error('SA stores error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch stores.' });
  }
});

router.post('/superadmin/stores', authSuperAdmin, async (req, res) => {
  try {
    const { name, address, phone, city, owner_phone, owner_password, plan } = req.body;

    if (!name || !owner_phone || !owner_password)
      return res.status(400).json({ error: 'Store name, owner phone and password required.' });

    const qrValue = `NIVO_${name.replace(/\s+/g, '_').toUpperCase()}_${Date.now()}`;

    const { data: store, error: storeError } = await supabase
      .from('stores')
      .insert({ name, address, phone, city, entry_qr_code: qrValue, plan: plan || 'Basic', is_active: true })
      .select().single();

    if (storeError) throw storeError;

    const hashedPassword = await bcrypt.hash(owner_password, 10);
    const { data: existingUser } = await supabase.from('users').select('id').eq('phone', owner_phone).single();

    if (existingUser) {
      await supabase.from('users')
        .update({ role: 'store_owner', store_id: store.id, admin_password: hashedPassword })
        .eq('id', existingUser.id);
    } else {
      await supabase.from('users')
        .insert({ phone: owner_phone, role: 'store_owner', store_id: store.id, admin_password: hashedPassword });
    }

    const qrImage = await QRCode.toDataURL(qrValue, { width: 400, margin: 2 });

    return res.json({ success: true, message: 'Store created successfully.', store, qr_image: qrImage, qr_code_value: qrValue });

  } catch (error) {
    console.error('Create store error:', error.message);
    return res.status(500).json({ error: 'Failed to create store.' });
  }
});

router.put('/superadmin/stores/:id/billing', authSuperAdmin, async (req, res) => {
  try {
    const { is_active, plan } = req.body;
    const { error } = await supabase.from('stores').update({ is_active, plan }).eq('id', req.params.id);
    if (error) throw error;
    return res.json({ success: true, message: `Store ${is_active ? 'enabled' : 'disabled'} successfully.` });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to update billing.' });
  }
});

module.exports = router;