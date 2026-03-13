const express = require('express');
const router = express.Router();
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
const QRCode = require('qrcode');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ── MIDDLEWARE: Authenticate Admin ───────────────────────
const authAdmin = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token. Please login.' });
    }
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (!['store_owner', 'super_admin'].includes(decoded.role)) {
      return res.status(403).json({ error: 'Access denied.' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
};

// ── MIDDLEWARE: Super Admin Only ─────────────────────────
const authSuperAdmin = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token.' });
    }
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.role !== 'super_admin') {
      return res.status(403).json({ error: 'Super admin access only.' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
};

// ════════════════════════════════════════════════════════
// AUTH
// ════════════════════════════════════════════════════════

// POST /api/admin/login
router.post('/login', async (req, res) => {
  try {
    const { phone, password } = req.body;

    if (!phone || !password) {
      return res.status(400).json({ error: 'Phone and password required.' });
    }

    // Find user with admin role
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('phone', phone)
      .in('role', ['store_owner', 'super_admin'])
      .single();

    if (error || !user) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    // Check password
    const isValid = await bcrypt.compare(password, user.admin_password);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    // Get store info if store owner
    let store = null;
    if (user.role === 'store_owner' && user.store_id) {
      const { data: storeData } = await supabase
        .from('stores')
        .select('id, name, address')
        .eq('id', user.store_id)
        .single();
      store = storeData;
    }

    // Generate JWT
    const token = jwt.sign(
      {
        id:       user.id,
        phone:    user.phone,
        role:     user.role,
        store_id: user.store_id || null,
      },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.json({
      success: true,
      token,
      role:  user.role,
      phone: user.phone,
      store,
    });

  } catch (error) {
    console.error('Admin login error:', error.message);
    return res.status(500).json({ error: 'Login failed.' });
  }
});

// ════════════════════════════════════════════════════════
// STORE OWNER — DASHBOARD STATS
// ════════════════════════════════════════════════════════

// GET /api/admin/stats
router.get('/stats', authAdmin, async (req, res) => {
  try {
    const store_id = req.user.store_id;
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    const monthStart = new Date();
    monthStart.setDate(1);
    monthStart.setHours(0, 0, 0, 0);

    // Today's revenue
    const { data: todayOrders } = await supabase
      .from('orders')
      .select('total_amount')
      .eq('store_id', store_id)
      .eq('status', 'paid')
      .gte('created_at', todayStart.toISOString());

    // Month revenue
    const { data: monthOrders } = await supabase
      .from('orders')
      .select('total_amount')
      .eq('store_id', store_id)
      .eq('status', 'paid')
      .gte('created_at', monthStart.toISOString());

    // Live sessions
    const { data: liveSessions } = await supabase
      .from('sessions')
      .select('id')
      .eq('store_id', store_id)
      .eq('status', 'active');

    // Product count
    const { count: productCount } = await supabase
      .from('store_products')
      .select('id', { count: 'exact' })
      .eq('store_id', store_id)
      .eq('is_available', true);

    // Today order count
    const { count: todayOrderCount } = await supabase
      .from('orders')
      .select('id', { count: 'exact' })
      .eq('store_id', store_id)
      .gte('created_at', todayStart.toISOString());

    const todayRevenue  = todayOrders?.reduce((s, o) => s + (o.total_amount || 0), 0) || 0;
    const monthRevenue  = monthOrders?.reduce((s, o) => s + (o.total_amount || 0), 0) || 0;

    return res.json({
      today_revenue:   todayRevenue,
      month_revenue:   monthRevenue,
      today_orders:    todayOrderCount || 0,
      live_sessions:   liveSessions?.length || 0,
      product_count:   productCount || 0,
    });

  } catch (error) {
    console.error('Stats error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch stats.' });
  }
});

// ════════════════════════════════════════════════════════
// ORDERS
// ════════════════════════════════════════════════════════

// GET /api/admin/orders?status=all&page=1&limit=20
router.get('/orders', authAdmin, async (req, res) => {
  try {
    const store_id = req.user.store_id;
    const { status, page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;

    let query = supabase
      .from('orders')
      .select(`
        id, total_amount, status, payment_id, created_at,
        users(phone)
      `)
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    // Super admin sees all orders, owner sees their store only
    if (req.user.role === 'store_owner') {
      query = query.eq('store_id', store_id);
    }

    if (status && status !== 'all') {
      query = query.eq('status', status);
    }

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

// GET /api/admin/sessions/live
router.get('/sessions/live', authAdmin, async (req, res) => {
  try {
    const store_id = req.user.store_id;

    const { data: sessions, error } = await supabase
      .from('sessions')
      .select(`
        id, created_at, user_id,
        users(phone),
        cart_items(
          quantity,
          store_products(price, products(name))
        )
      `)
      .eq('store_id', store_id)
      .eq('status', 'active')
      .order('created_at', { ascending: false });

    if (error) throw error;

    const enriched = (sessions || []).map(s => {
      const items = s.cart_items || [];
      const total = items.reduce((sum, item) => {
        return sum + (item.quantity * (item.store_products?.price || 0));
      }, 0);
      const minutesAgo = Math.floor(
        (Date.now() - new Date(s.created_at).getTime()) / 60000
      );
      return {
        session_id:   s.id,
        phone:        s.users?.phone || 'Unknown',
        item_count:   items.length,
        cart_total:   total,
        minutes_ago:  minutesAgo,
        cart: items.map(i => ({
          name:     i.store_products?.products?.name || 'Unknown',
          quantity: i.quantity,
          price:    i.store_products?.price || 0,
        })),
      };
    });

    return res.json({ success: true, sessions: enriched });

  } catch (error) {
    console.error('Live sessions error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch live sessions.' });
  }
});

// ════════════════════════════════════════════════════════
// PRODUCTS
// ════════════════════════════════════════════════════════

// GET /api/admin/products
router.get('/products', authAdmin, async (req, res) => {
  try {
    const store_id = req.user.store_id;

    const { data: products, error } = await supabase
      .from('store_products')
      .select(`
        id, price, stock_quantity, is_available,
        products(id, name, barcode, brand, category)
      `)
      .eq('store_id', store_id)
      .order('created_at', { ascending: false });

    if (error) throw error;

    const flat = (products || []).map(sp => ({
      store_product_id: sp.id,
      product_id:       sp.products?.id,
      name:             sp.products?.name,
      barcode:          sp.products?.barcode,
      brand:            sp.products?.brand,
      category:         sp.products?.category,
      price:            sp.price,
      stock:            sp.stock_quantity,
      available:        sp.is_available,
    }));

    return res.json({ success: true, products: flat });

  } catch (error) {
    console.error('Products error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch products.' });
  }
});

// POST /api/admin/products
router.post('/products', authAdmin, async (req, res) => {
  try {
    const store_id = req.user.store_id;
    const { barcode, name, brand, category, price, stock, available = true } = req.body;

    if (!barcode || !name || !price) {
      return res.status(400).json({ error: 'Barcode, name and price are required.' });
    }

    // Upsert into global products table
    const { data: product, error: prodError } = await supabase
      .from('products')
      .upsert({ barcode, name, brand, category }, { onConflict: 'barcode' })
      .select()
      .single();

    if (prodError) throw prodError;

    // Upsert into store_products
    const { data: storeProduct, error: spError } = await supabase
      .from('store_products')
      .upsert({
        store_id,
        product_id:     product.id,
        price:          parseFloat(price),
        stock_quantity: parseInt(stock) || 0,
        is_available:   available,
      }, { onConflict: 'store_id,product_id' })
      .select()
      .single();

    if (spError) throw spError;

    return res.json({
      success: true,
      message: 'Product added successfully.',
      product: { ...product, ...storeProduct },
    });

  } catch (error) {
    console.error('Add product error:', error.message);
    return res.status(500).json({ error: 'Failed to add product.' });
  }
});

// PUT /api/admin/products/:id
router.put('/products/:id', authAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const store_id = req.user.store_id;
    const { name, brand, category, price, stock, available } = req.body;

    // Update store_products
    const { error } = await supabase
      .from('store_products')
      .update({
        price:          parseFloat(price),
        stock_quantity: parseInt(stock),
        is_available:   available,
      })
      .eq('id', id)
      .eq('store_id', store_id);

    if (error) throw error;

    // Update global product name/brand/category if provided
    if (name || brand || category) {
      const { data: sp } = await supabase
        .from('store_products')
        .select('product_id')
        .eq('id', id)
        .single();

      if (sp) {
        await supabase
          .from('products')
          .update({ name, brand, category })
          .eq('id', sp.product_id);
      }
    }

    return res.json({ success: true, message: 'Product updated.' });

  } catch (error) {
    console.error('Update product error:', error.message);
    return res.status(500).json({ error: 'Failed to update product.' });
  }
});

// DELETE /api/admin/products/:id
router.delete('/products/:id', authAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const store_id = req.user.store_id;

    const { error } = await supabase
      .from('store_products')
      .delete()
      .eq('id', id)
      .eq('store_id', store_id);

    if (error) throw error;

    return res.json({ success: true, message: 'Product removed from store.' });

  } catch (error) {
    console.error('Delete product error:', error.message);
    return res.status(500).json({ error: 'Failed to remove product.' });
  }
});

// ════════════════════════════════════════════════════════
// STORE QR CODE
// ════════════════════════════════════════════════════════

// GET /api/admin/store/qr
router.get('/store/qr', authAdmin, async (req, res) => {
  try {
    const store_id = req.user.store_id;

    const { data: store, error } = await supabase
      .from('stores')
      .select('name, entry_qr_code')
      .eq('id', store_id)
      .single();

    if (error || !store) {
      return res.status(404).json({ error: 'Store not found.' });
    }

    // Generate QR code as base64 PNG
    const qrImage = await QRCode.toDataURL(store.entry_qr_code, {
      width: 400,
      margin: 2,
      color: { dark: '#000000', light: '#ffffff' },
    });

    return res.json({
      success:        true,
      qr_image:       qrImage,
      qr_code_value:  store.entry_qr_code,
      store_name:     store.name,
    });

  } catch (error) {
    console.error('Store QR error:', error.message);
    return res.status(500).json({ error: 'Failed to generate QR code.' });
  }
});

// ════════════════════════════════════════════════════════
// STORE SETTINGS
// ════════════════════════════════════════════════════════

// GET /api/admin/store
router.get('/store', authAdmin, async (req, res) => {
  try {
    const store_id = req.user.store_id;

    const { data: store, error } = await supabase
      .from('stores')
      .select('*')
      .eq('id', store_id)
      .single();

    if (error) throw error;

    return res.json({ success: true, store });

  } catch (error) {
    console.error('Store settings error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch store settings.' });
  }
});

// PUT /api/admin/store
router.put('/store', authAdmin, async (req, res) => {
  try {
    const store_id = req.user.store_id;
    const { name, address, phone } = req.body;

    const { error } = await supabase
      .from('stores')
      .update({ name, address, phone })
      .eq('id', store_id);

    if (error) throw error;

    return res.json({ success: true, message: 'Store updated.' });

  } catch (error) {
    console.error('Update store error:', error.message);
    return res.status(500).json({ error: 'Failed to update store.' });
  }
});

// ════════════════════════════════════════════════════════
// ANALYTICS
// ════════════════════════════════════════════════════════

// GET /api/admin/analytics
router.get('/analytics', authAdmin, async (req, res) => {
  try {
    const store_id = req.user.store_id;

    // Last 30 days revenue per day
    const { data: orders } = await supabase
      .from('orders')
      .select('total_amount, created_at')
      .eq('store_id', store_id)
      .eq('status', 'paid')
      .gte('created_at', new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString());

    // Group by day
    const revenueByDay = {};
    (orders || []).forEach(o => {
      const day = new Date(o.created_at).toLocaleDateString('en-IN', { day: '2-digit', month: 'short' });
      revenueByDay[day] = (revenueByDay[day] || 0) + (o.total_amount || 0);
    });
    const revenueChart = Object.entries(revenueByDay).map(([day, rev]) => ({ day, rev }));

    // Top products
    const { data: topItems } = await supabase
      .from('order_items')
      .select(`
        quantity,
        store_products(
          price,
          products(name)
        ),
        orders!inner(store_id, status)
      `)
      .eq('orders.store_id', store_id)
      .eq('orders.status', 'paid');

    const productMap = {};
    (topItems || []).forEach(item => {
      const name = item.store_products?.products?.name || 'Unknown';
      const price = item.store_products?.price || 0;
      if (!productMap[name]) productMap[name] = { name, units: 0, revenue: 0 };
      productMap[name].units   += item.quantity;
      productMap[name].revenue += item.quantity * price;
    });
    const topProducts = Object.values(productMap)
      .sort((a, b) => b.units - a.units)
      .slice(0, 5);

    return res.json({
      success:       true,
      revenue_chart: revenueChart,
      top_products:  topProducts,
    });

  } catch (error) {
    console.error('Analytics error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch analytics.' });
  }
});

// ════════════════════════════════════════════════════════
// USERS (store owner sees their customers)
// ════════════════════════════════════════════════════════

// GET /api/admin/users
router.get('/users', authAdmin, async (req, res) => {
  try {
    const { data: users, error } = await supabase
      .from('users')
      .select('id, phone, role, created_at')
      .eq('role', 'customer')
      .order('created_at', { ascending: false });

    if (error) throw error;

    return res.json({ success: true, users: users || [] });

  } catch (error) {
    console.error('Users error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch users.' });
  }
});

// ════════════════════════════════════════════════════════
// SUPER ADMIN ROUTES
// ════════════════════════════════════════════════════════

// GET /api/admin/superadmin/stores
router.get('/superadmin/stores', authSuperAdmin, async (req, res) => {
  try {
    const { data: stores, error } = await supabase
      .from('stores')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;

    // Get order count and revenue per store
    const enriched = await Promise.all((stores || []).map(async store => {
      const { data: orders } = await supabase
        .from('orders')
        .select('total_amount')
        .eq('store_id', store.id)
        .eq('status', 'paid');

      const revenue = (orders || []).reduce((s, o) => s + (o.total_amount || 0), 0);

      return {
        ...store,
        order_count: orders?.length || 0,
        total_revenue: revenue,
      };
    }));

    return res.json({ success: true, stores: enriched });

  } catch (error) {
    console.error('SA stores error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch stores.' });
  }
});

// POST /api/admin/superadmin/stores
router.post('/superadmin/stores', authSuperAdmin, async (req, res) => {
  try {
    const { name, address, phone, city, owner_phone, owner_password, plan } = req.body;

    if (!name || !owner_phone || !owner_password) {
      return res.status(400).json({ error: 'Store name, owner phone and password required.' });
    }

    // Generate unique QR code
    const qrValue = `NIVO_${name.replace(/\s+/g, '_').toUpperCase()}_${Date.now()}`;

    // Create store
    const { data: store, error: storeError } = await supabase
      .from('stores')
      .insert({
        name,
        address,
        phone,
        city,
        entry_qr_code: qrValue,
        plan:          plan || 'Basic',
        is_active:     true,
      })
      .select()
      .single();

    if (storeError) throw storeError;

    // Hash password
    const hashedPassword = await bcrypt.hash(owner_password, 10);

    // Create or update owner user
    const { data: existingUser } = await supabase
      .from('users')
      .select('id')
      .eq('phone', owner_phone)
      .single();

    if (existingUser) {
      await supabase
        .from('users')
        .update({
          role:           'store_owner',
          store_id:       store.id,
          admin_password: hashedPassword,
        })
        .eq('id', existingUser.id);
    } else {
      await supabase
        .from('users')
        .insert({
          phone:          owner_phone,
          role:           'store_owner',
          store_id:       store.id,
          admin_password: hashedPassword,
        });
    }

    // Generate QR image
    const qrImage = await QRCode.toDataURL(qrValue, {
      width: 400,
      margin: 2,
    });

    return res.json({
      success:        true,
      message:        'Store created successfully.',
      store,
      qr_image:       qrImage,
      qr_code_value:  qrValue,
    });

  } catch (error) {
    console.error('Create store error:', error.message);
    return res.status(500).json({ error: 'Failed to create store.' });
  }
});

// PUT /api/admin/superadmin/stores/:id/billing
router.put('/superadmin/stores/:id/billing', authSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { is_active, plan } = req.body;

    const { error } = await supabase
      .from('stores')
      .update({ is_active, plan })
      .eq('id', id);

    if (error) throw error;

    return res.json({
      success: true,
      message: `Store ${is_active ? 'enabled' : 'disabled'} successfully.`
    });

  } catch (error) {
    console.error('Billing error:', error.message);
    return res.status(500).json({ error: 'Failed to update billing.' });
  }
});

// GET /api/admin/superadmin/stats
router.get('/superadmin/stats', authSuperAdmin, async (req, res) => {
  try {
    const { count: storeCount } = await supabase
      .from('stores')
      .select('id', { count: 'exact' })
      .eq('is_active', true);

    const { count: userCount } = await supabase
      .from('users')
      .select('id', { count: 'exact' })
      .eq('role', 'customer');

    const { count: orderCount } = await supabase
      .from('orders')
      .select('id', { count: 'exact' });

    const { data: revenue } = await supabase
      .from('orders')
      .select('total_amount')
      .eq('status', 'paid');

    const totalRevenue = (revenue || []).reduce((s, o) => s + (o.total_amount || 0), 0);

    return res.json({
      success:        true,
      store_count:    storeCount || 0,
      user_count:     userCount  || 0,
      order_count:    orderCount || 0,
      total_revenue:  totalRevenue,
    });

  } catch (error) {
    console.error('SA stats error:', error.message);
    return res.status(500).json({ error: 'Failed to fetch platform stats.' });
  }
});

module.exports = router;