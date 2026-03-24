const express = require('express');
const router = express.Router();
const axios = require('axios');
const db = require('../db');
const { authenticate } = require('../middleware/auth'); // ✅ FIXED IMPORT

// ─────────────────────────────────────────────
// GET PRODUCT BY BARCODE
// ─────────────────────────────────────────────
router.get('/:barcode', authenticate, async (req, res) => {
  const { barcode } = req.params;
  const { store_id } = req.query;

  // ✅ Validate input
  if (!store_id) {
    return res.status(400).json({ error: 'store_id is required' });
  }

  try {
    // ✅ Step 1: Check product in DB (WITH store mapping)
    const result = await db.query(
      `SELECT 
          p.id, p.barcode, p.name, p.brand, p.image_url, p.category, p.quantity,
          sp.price, sp.mrp, sp.gst_percent, sp.in_stock
       FROM products p
       JOIN store_products sp ON sp.product_id = p.id
       WHERE p.barcode = $1 AND sp.store_id = $2`,
      [barcode, store_id]
    );

    // ✅ Product found in store
    if (result.rows.length > 0) {
      const product = result.rows[0];

      // ❗ Out of stock handling
      if (!product.in_stock) {
        return res.json({
          found: true,
          in_stock: false,
          message: 'Out of stock',
          product
        });
      }

      // ✅ Log scan event
      await logScan(req.user.id, store_id, product.id, barcode, 'scanned');

      return res.json({
        found: true,
        source: 'database',
        product
      });
    }

    // ─────────────────────────────────────────────
    // Step 2: Try external API (fallback)
    // ─────────────────────────────────────────────
    try {
      const ext = await axios.get(
        `https://world.openfoodfacts.org/api/v0/product/${barcode}.json`,
        { timeout: 5000 }
      );

      if (ext.data.status === 1 && ext.data.product) {
        const p = ext.data.product;

        // ✅ Insert into products table (if not exists)
        const insertRes = await db.query(
          `INSERT INTO products (barcode, name, brand, image_url, category, quantity)
           VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (barcode) DO NOTHING
           RETURNING id`,
          [
            barcode,
            p.product_name || 'Unknown',
            p.brands || '',
            p.image_url || '',
            p.categories || '',
            p.quantity || ''
          ]
        );

        // ✅ Get product id (existing or inserted)
        let productId;
        if (insertRes.rows.length > 0) {
          productId = insertRes.rows[0].id;
        } else {
          const existing = await db.query(
            `SELECT id FROM products WHERE barcode = $1`,
            [barcode]
          );
          productId = existing.rows[0]?.id;
        }

        // ⚠️ IMPORTANT: Add to store_products (THIS WAS YOUR BUG)
        if (productId) {
          await db.query(
            `INSERT INTO store_products (store_id, product_id, price, mrp, gst_percent, in_stock)
             VALUES ($1, $2, 0, 0, 0, true)
             ON CONFLICT (store_id, product_id) DO NOTHING`,
            [store_id, productId]
          );
        }

        return res.json({
          found: true,
          source: 'external',
          price_needed: true,
          product: {
            barcode,
            name: p.product_name || 'Unknown',
            brand: p.brands || '',
            image_url: p.image_url || '',
            price: null
          }
        });
      }
    } catch (e) {
      console.log('Open Food Facts unavailable:', e.message);
    }

    // ❌ Final fallback
    return res.status(404).json({
      found: false,
      message: 'Product not found. Ask store staff.'
    });

  } catch (error) {
    console.error('Product fetch error:', error);
    return res.status(500).json({ error: 'Could not fetch product' });
  }
});

// ─────────────────────────────────────────────
// LOG SCAN EVENT
// ─────────────────────────────────────────────
const logScan = async (userId, storeId, productId, barcode, action) => {
  try {
    await db.query(
      `INSERT INTO scan_events 
       (user_id, store_id, product_id, barcode, action) 
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, storeId, productId, barcode, action]
    );
  } catch (e) {
    console.log('Scan log failed:', e.message);
  }
};

module.exports = router;