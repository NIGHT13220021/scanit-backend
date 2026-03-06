const express = require('express');
const router = express.Router();
const db = require('../db');
const { authenticate } = require('../middleware/auth');

router.post('/add', authenticate, async (req, res) => {
  const { session_id, product_id, quantity = 1 } = req.body;
  try {
    const session = await db.query(
      "SELECT * FROM sessions WHERE id = $1 AND user_id = $2 AND status = 'active'",
      [session_id, req.user.id]
    );
    if (session.rows.length === 0) return res.status(403).json({ error: 'Invalid session' });
    const product = await db.query(
      `SELECT sp.price, p.name FROM store_products sp 
       JOIN products p ON p.id = sp.product_id 
       WHERE sp.product_id = $1 AND sp.store_id = $2`,
      [product_id, session.rows[0].store_id]
    );
    if (product.rows.length === 0) return res.status(404).json({ error: 'Product not in this store' });
    const existing = await db.query(
      'SELECT * FROM cart_items WHERE session_id = $1 AND product_id = $2',
      [session_id, product_id]
    );
    if (existing.rows.length > 0) {
      await db.query(
        'UPDATE cart_items SET quantity = quantity + $1 WHERE session_id = $2 AND product_id = $3',
        [quantity, session_id, product_id]
      );
    } else {
      await db.query(
        'INSERT INTO cart_items (session_id, product_id, quantity, price_at_scan) VALUES ($1, $2, $3, $4)',
        [session_id, product_id, quantity, product.rows[0].price]
      );
    }
    res.json({ success: true, message: `${product.rows[0].name} added to cart` });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not add to cart' });
  }
});

router.post('/remove', authenticate, async (req, res) => {
  const { session_id, product_id } = req.body;
  try {
    const session = await db.query(
      "SELECT * FROM sessions WHERE id = $1 AND user_id = $2 AND status = 'active'",
      [session_id, req.user.id]
    );
    if (session.rows.length === 0) return res.status(403).json({ error: 'Invalid session' });
    await db.query('DELETE FROM cart_items WHERE session_id = $1 AND product_id = $2', [session_id, product_id]);
    res.json({ success: true, message: 'Item removed' });
  } catch (error) {
    res.status(500).json({ error: 'Could not remove item' });
  }
});

router.get('/:session_id', authenticate, async (req, res) => {
  const { session_id } = req.params;
  try {
    const session = await db.query(
      "SELECT * FROM sessions WHERE id = $1 AND user_id = $2 AND status = 'active'",
      [session_id, req.user.id]
    );
    if (session.rows.length === 0) return res.status(403).json({ error: 'Invalid session' });
    const items = await db.query(
      `SELECT ci.id, ci.quantity, ci.price_at_scan,
              p.id as product_id, p.name, p.brand, p.image_url, p.barcode,
              sp.gst_percent, (ci.quantity * ci.price_at_scan) as item_total
       FROM cart_items ci
       JOIN products p ON p.id = ci.product_id
       JOIN store_products sp ON sp.product_id = p.id AND sp.store_id = $2
       WHERE ci.session_id = $1 ORDER BY ci.added_at DESC`,
      [session_id, session.rows[0].store_id]
    );
    const rows = items.rows;
    const subtotal = rows.reduce((s, i) => s + parseFloat(i.item_total), 0);
    res.json({
      success: true, items: rows,
      summary: { item_count: rows.length, subtotal: subtotal.toFixed(2), total: subtotal.toFixed(2) }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not get cart' });
  }
});
router.post('/update', authenticate, async (req, res) => {
  const { session_id, product_id, quantity } = req.body;
  try {
    await db.query(
      `UPDATE cart_items SET quantity = $1 
       WHERE session_id = $2 AND product_id = $3`,
      [quantity, session_id, product_id]
    );
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Could not update cart' });
  }
});

module.exports = router;