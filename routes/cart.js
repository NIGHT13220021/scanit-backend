const express = require('express');
const router = express.Router();
const db = require('../db');
const { authenticate } = require('../middleware/auth');

// ADD item by barcode
router.post('/add', authenticate, async (req, res) => {
  const { session_id, barcode } = req.body;
  try {
    const session = await db.query(
      "SELECT * FROM sessions WHERE id = $1 AND user_id = $2 AND status = 'active'",
      [session_id, req.user.id]
    );
    if (session.rows.length === 0) return res.status(403).json({ error: 'Invalid session' });

    // Use store_products join to get price
    const product = await db.query(
      `SELECT p.*, sp.price, sp.mrp, sp.gst_percent, sp.in_stock
       FROM products p
       JOIN store_products sp ON sp.product_id = p.id
       WHERE p.barcode = $1 AND sp.store_id = $2`,
      [barcode, session.rows[0].store_id]
    );

    if (product.rows.length === 0) return res.status(404).json({ error: 'Product not in this store' });

    const p = product.rows[0];

    if (!p.in_stock) return res.status(400).json({ error: 'Product is out of stock' });

    const existing = await db.query(
      'SELECT * FROM cart_items WHERE session_id = $1 AND product_id = $2',
      [session_id, p.id]
    );

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

    res.json({ success: true, message: `${p.name} added to cart`, product: { name: p.name, price: p.price } });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not add to cart' });
  }
});

// REMOVE item by cart item id
router.delete('/remove/:item_id', authenticate, async (req, res) => {
  const { item_id } = req.params;
  try {
    await db.query('DELETE FROM cart_items WHERE id = $1', [item_id]);
    res.json({ success: true, message: 'Item removed' });
  } catch (error) {
    res.status(500).json({ error: 'Could not remove item' });
  }
});

// GET cart items
router.get('/:session_id', authenticate, async (req, res) => {
  const { session_id } = req.params;
  try {
    const session = await db.query(
      "SELECT * FROM sessions WHERE id = $1 AND user_id = $2 AND status = 'active'",
      [session_id, req.user.id]
    );
    if (session.rows.length === 0) return res.status(403).json({ error: 'Invalid session' });

    const items = await db.query(
      `SELECT ci.id, ci.quantity, ci.price_at_scan as price,
              p.id as product_id, p.name, p.brand, p.barcode,
              (ci.quantity * ci.price_at_scan) as item_total
       FROM cart_items ci
       JOIN products p ON p.id = ci.product_id
       WHERE ci.session_id = $1
       ORDER BY ci.id DESC`,
      [session_id]
    );

    const rows = items.rows;
    const subtotal = rows.reduce((s, i) => s + parseFloat(i.item_total), 0);

    res.json({
      success: true,
      items: rows,
      summary: {
        item_count: rows.length,
        subtotal: subtotal.toFixed(2),
        total: subtotal.toFixed(2)
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not get cart' });
  }
});

// UPDATE quantity
router.post('/update', authenticate, async (req, res) => {
  const { session_id, product_id, quantity } = req.body;
  try {
    if (quantity <= 0) {
      await db.query(
        'DELETE FROM cart_items WHERE session_id = $1 AND product_id = $2',
        [session_id, product_id]
      );
    } else {
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