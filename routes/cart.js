const express = require('express');
const router = express.Router();
const db = require('../db');
const { authenticate } = require('../middleware/auth');

// ─────────────────────────────────────────────
// ADD item by barcode
// ─────────────────────────────────────────────
router.post('/add', authenticate, async (req, res) => {
  const { session_id, barcode } = req.body;
  try {
    const session = await db.query(
      "SELECT * FROM sessions WHERE id = $1 AND user_id = $2 AND status = 'active'",
      [session_id, req.user.id]
    );
    if (session.rows.length === 0)
      return res.status(403).json({ error: 'Invalid session' });

    const product = await db.query(
      `SELECT p.*, sp.price, sp.mrp, sp.gst_percent, sp.in_stock, sp.stock_quantity
       FROM products p
       JOIN store_products sp ON sp.product_id = p.id
       WHERE p.barcode = $1 AND sp.store_id = $2`,
      [barcode, session.rows[0].store_id]
    );

    if (product.rows.length === 0)
      return res.status(404).json({ error: 'Product not in this store' });

    const p = product.rows[0];

    // ── Out of stock ──────────────────────────────────────────
    if (!p.in_stock) {
      return res.status(400).json({
        error:        `${p.name} is out of stock`,
        out_of_stock: true,          // ← frontend checks this
        product_name: p.name,
      });
    }

    const existing = await db.query(
      'SELECT * FROM cart_items WHERE session_id = $1 AND product_id = $2',
      [session_id, p.id]
    );

    // ── Stock quantity limit ───────────────────────────────────
    if (p.stock_quantity !== null) {
      const currentQty = existing.rows.length > 0 ? existing.rows[0].quantity : 0;
      if (currentQty + 1 > p.stock_quantity) {
        return res.status(400).json({
          error:           `Only ${p.stock_quantity} unit${p.stock_quantity === 1 ? '' : 's'} of "${p.name}" available in store`,
          stock_limit:     true,       // ← frontend checks this
          available:       p.stock_quantity,
          already_in_cart: currentQty,
          product_name:    p.name,
        });
      }
    }

    if (existing.rows.length > 0) {
      await db.query(
        'UPDATE cart_items SET quantity = quantity + 1 WHERE session_id = $1 AND product_id = $2',
        [session_id, p.id]
      );
    } else {
      await db.query(
        'INSERT INTO cart_items (session_id, product_id, quantity, price_at_scan) VALUES ($1, $2, $3, $4)',
        [session_id, p.id, 1, p.price]
      );
    }

    res.json({
      success: true,
      message: `${p.name} added to cart`,
      item: {
        name:           p.name,
        price:          p.price,
        stock_quantity: p.stock_quantity,
      }
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not add to cart' });
  }
});

// ─────────────────────────────────────────────
// REMOVE item
// ─────────────────────────────────────────────
router.delete('/remove/:item_id', authenticate, async (req, res) => {
  try {
    await db.query('DELETE FROM cart_items WHERE id = $1', [req.params.item_id]);
    res.json({ success: true, message: 'Item removed' });
  } catch (error) {
    res.status(500).json({ error: 'Could not remove item' });
  }
});

// ─────────────────────────────────────────────
// GET cart items  ← now returns stock_quantity
// ─────────────────────────────────────────────
router.get('/:session_id', authenticate, async (req, res) => {
  const { session_id } = req.params;
  try {
    const session = await db.query(
      "SELECT * FROM sessions WHERE id = $1 AND user_id = $2 AND status = 'active'",
      [session_id, req.user.id]
    );
    if (session.rows.length === 0)
      return res.status(403).json({ error: 'Invalid session' });

    const items = await db.query(
      `SELECT
          ci.id,
          ci.quantity,
          ci.price_at_scan          AS price,
          p.id                      AS product_id,
          p.name,
          p.brand,
          p.barcode,
          sp.stock_quantity,         -- ← needed for stock badge in UI
          sp.max_stock,
          (ci.quantity * ci.price_at_scan) AS item_total
       FROM cart_items ci
       JOIN products p       ON p.id  = ci.product_id
       JOIN store_products sp ON sp.product_id = p.id
                              AND sp.store_id   = $2
       WHERE ci.session_id = $1
       ORDER BY ci.id DESC`,
      [session_id, session.rows[0].store_id]
    );

    const rows     = items.rows;
    const subtotal = rows.reduce((s, i) => s + parseFloat(i.item_total), 0);

    res.json({
      success: true,
      items: rows,
      summary: {
        item_count: rows.length,
        subtotal:   subtotal.toFixed(2),
        total:      subtotal.toFixed(2),
      }
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not get cart' });
  }
});

// ─────────────────────────────────────────────
// UPDATE quantity
// ─────────────────────────────────────────────
router.post('/update', authenticate, async (req, res) => {
  const { session_id, product_id, quantity } = req.body;
  try {
    if (quantity <= 0) {
      await db.query(
        'DELETE FROM cart_items WHERE session_id = $1 AND product_id = $2',
        [session_id, product_id]
      );
    } else {
      const session = await db.query(
        "SELECT store_id FROM sessions WHERE id = $1 AND user_id = $2 AND status = 'active'",
        [session_id, req.user.id]
      );

      if (session.rows.length > 0) {
        const stock = await db.query(
          `SELECT sp.stock_quantity, p.name
           FROM store_products sp
           JOIN products p ON p.id = sp.product_id
           WHERE sp.product_id = $1 AND sp.store_id = $2`,
          [product_id, session.rows[0].store_id]
        );

        if (stock.rows.length > 0 && stock.rows[0].stock_quantity !== null) {
          if (quantity > stock.rows[0].stock_quantity) {
            return res.status(400).json({
              error:        `Only ${stock.rows[0].stock_quantity} unit${stock.rows[0].stock_quantity === 1 ? '' : 's'} of "${stock.rows[0].name}" available`,
              stock_limit:  true,        // ← frontend checks this
              available:    stock.rows[0].stock_quantity,
              product_name: stock.rows[0].name,
            });
          }
        }
      }

      await db.query(
        'UPDATE cart_items SET quantity = $1 WHERE session_id = $2 AND product_id = $3',
        [quantity, session_id, product_id]
      );
    }

    res.json({ success: true });

  } catch (error) {
    res.status(500).json({ error: 'Could not update cart' });
  }
});

module.exports = router;