const express = require('express');
const router = express.Router();
const db = require('../db');
const { authenticateAdmin: authenticate } = require('../middleware/auth');

// ─────────────────────────────────────────────
// GET ALL PRODUCTS FOR STORE
// ─────────────────────────────────────────────
router.get('/', authenticateAdmin, async (req, res) => {
  const { store_id } = req.admin;

  try {
    const result = await db.query(
      `SELECT
         sp.id            AS store_product_id,
         sp.store_id,
         sp.price,
         sp.mrp,
         sp.gst_percent,
         sp.in_stock,
         sp.stock_quantity,   -- ← FIX: include stock_quantity
         sp.max_stock,        -- ← FIX: include max_stock
         p.id             AS product_id,
         p.barcode,
         p.name,
         p.brand,
         p.image_url,
         p.category,
         p.quantity       AS unit_quantity,
         p.created_at
       FROM store_products sp
       JOIN products p ON p.id = sp.product_id
       WHERE sp.store_id = $1
       ORDER BY p.name ASC`,
      [store_id]
    );

    return res.json({ products: result.rows });
  } catch (err) {
    console.error('GET products error:', err);
    return res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// ─────────────────────────────────────────────
// ADD PRODUCT
// ─────────────────────────────────────────────
router.post('/', authenticateAdmin, async (req, res) => {
  const { store_id } = req.admin;
  const {
    barcode, name, brand = '', category = '',
    price = 0, in_stock = true,
    stock_quantity = null, max_stock = null
  } = req.body;

  if (!barcode || !name) {
    return res.status(400).json({ error: 'barcode and name are required' });
  }

  try {
    // 1. Upsert into products table
    const productRes = await db.query(
      `INSERT INTO products (barcode, name, brand, category)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (barcode) DO UPDATE
         SET name     = EXCLUDED.name,
             brand    = EXCLUDED.brand,
             category = EXCLUDED.category
       RETURNING id`,
      [barcode, name, brand, category]
    );
    const productId = productRes.rows[0].id;

    // 2. Upsert into store_products with stock fields
    const spRes = await db.query(
      `INSERT INTO store_products
         (store_id, product_id, price, mrp, gst_percent, in_stock, stock_quantity, max_stock)
       VALUES ($1, $2, $3, $3, 0, $4, $5, $6)
       ON CONFLICT (store_id, product_id) DO UPDATE
         SET price          = EXCLUDED.price,
             mrp            = EXCLUDED.mrp,
             in_stock       = EXCLUDED.in_stock,
             stock_quantity = EXCLUDED.stock_quantity,
             max_stock      = EXCLUDED.max_stock
       RETURNING id`,
      [store_id, productId, parseFloat(price) || 0, in_stock,
       stock_quantity !== '' && stock_quantity !== null ? parseInt(stock_quantity) : null,
       max_stock !== '' && max_stock !== null ? parseInt(max_stock) : null]
    );

    return res.json({ success: true, store_product_id: spRes.rows[0].id });
  } catch (err) {
    console.error('POST product error:', err);
    return res.status(500).json({ error: 'Failed to add product' });
  }
});

// ─────────────────────────────────────────────
// UPDATE PRODUCT
// ─────────────────────────────────────────────
router.put('/:id', authenticateAdmin, async (req, res) => {
  const { store_id } = req.admin;
  const { id } = req.params; // store_product_id
  const {
    barcode, name, brand = '', category = '',
    price = 0, in_stock = true,
    stock_quantity, max_stock
  } = req.body;

  try {
    // 1. Get the product_id from store_products
    const spCheck = await db.query(
      `SELECT product_id FROM store_products WHERE id = $1 AND store_id = $2`,
      [id, store_id]
    );
    if (!spCheck.rows.length) {
      return res.status(404).json({ error: 'Product not found' });
    }
    const productId = spCheck.rows[0].product_id;

    // 2. Update products table (name, brand, category, barcode)
    await db.query(
      `UPDATE products
       SET name = $1, brand = $2, category = $3, barcode = $4
       WHERE id = $5`,
      [name, brand, category, barcode, productId]
    );

    // 3. Update store_products — INCLUDING stock_quantity and max_stock
    await db.query(
      `UPDATE store_products
       SET price          = $1,
           mrp            = $1,
           in_stock       = $2,
           stock_quantity = $3,
           max_stock      = $4
       WHERE id = $5 AND store_id = $6`,
      [
        parseFloat(price) || 0,
        in_stock,
        stock_quantity !== '' && stock_quantity !== null && stock_quantity !== undefined
          ? parseInt(stock_quantity) : null,
        max_stock !== '' && max_stock !== null && max_stock !== undefined
          ? parseInt(max_stock) : null,
        id,
        store_id
      ]
    );

    return res.json({ success: true });
  } catch (err) {
    console.error('PUT product error:', err);
    return res.status(500).json({ error: 'Failed to update product' });
  }
});

// ─────────────────────────────────────────────
// DELETE PRODUCT FROM STORE
// ─────────────────────────────────────────────
router.delete('/:id', authenticateAdmin, async (req, res) => {
  const { store_id } = req.admin;
  const { id } = req.params;

  try {
    await db.query(
      `DELETE FROM store_products WHERE id = $1 AND store_id = $2`,
      [id, store_id]
    );
    return res.json({ success: true });
  } catch (err) {
    console.error('DELETE product error:', err);
    return res.status(500).json({ error: 'Failed to delete product' });
  }
});

// ─────────────────────────────────────────────
// PATCH STOCK QUANTITY ONLY (dashboard quick update)
// ─────────────────────────────────────────────
router.patch('/:id/qty', authenticateAdmin, async (req, res) => {
  const { store_id } = req.admin;
  const { id } = req.params;
  const { stock_quantity } = req.body;

  if (stock_quantity === undefined || stock_quantity === null) {
    return res.status(400).json({ error: 'stock_quantity is required' });
  }

  try {
    await db.query(
      `UPDATE store_products
       SET stock_quantity = $1
       WHERE id = $2 AND store_id = $3`,
      [parseInt(stock_quantity), id, store_id]
    );
    return res.json({ success: true });
  } catch (err) {
    console.error('PATCH qty error:', err);
    return res.status(500).json({ error: 'Failed to update stock quantity' });
  }
});

module.exports = router;