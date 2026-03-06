const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const db = require('../db');
const { authenticate } = require('../middleware/auth');
require('dotenv').config();

const generateOTP = () => 
  Math.floor(100000 + Math.random() * 900000).toString();

router.post('/send-otp', async (req, res) => {
  const { phone } = req.body;
  if (!phone || phone.length !== 10 || !/^\d+$/.test(phone)) {
    return res.status(400).json({ error: 'Enter valid 10 digit phone number' });
  }
  try {
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    await db.query('DELETE FROM otps WHERE phone = $1', [phone]);
    await db.query(
      'INSERT INTO otps (phone, otp, expires_at) VALUES ($1, $2, $3)',
      [phone, otp, expiresAt]
    );
    if (process.env.NODE_ENV === 'development') {
      console.log(`\n📱 OTP for ${phone}: ${otp}\n`);
    }
    res.json({ 
      success: true, 
      message: `OTP sent to ${phone}`,
      ...(process.env.NODE_ENV === 'development' && { otp })
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

router.post('/verify-otp', async (req, res) => {
  const { phone, otp } = req.body;
  if (!phone || !otp) {
    return res.status(400).json({ error: 'Phone and OTP required' });
  }
  try {
    const otpRecord = await db.query(
      `SELECT * FROM otps WHERE phone = $1 AND otp = $2 
       AND is_used = false AND expires_at > NOW()`,
      [phone, otp]
    );
    if (otpRecord.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }
    await db.query('UPDATE otps SET is_used = true WHERE id = $1', [otpRecord.rows[0].id]);
    let user = await db.query('SELECT * FROM users WHERE phone = $1', [phone]);
    if (user.rows.length === 0) {
      user = await db.query('INSERT INTO users (phone) VALUES ($1) RETURNING *', [phone]);
    }
    const userData = user.rows[0];
    if (userData.is_banned) {
      return res.status(403).json({ error: 'Account suspended. Contact support.' });
    }
    const token = jwt.sign(
      { id: userData.id, phone: userData.phone, role: 'customer' },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );
    res.json({
      success: true,
      token,
      user: { id: userData.id, phone: userData.phone, name: userData.name, is_new_user: !userData.name }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

router.post('/update-profile', authenticate, async (req, res) => {
  const { name, email } = req.body;
  try {
    await db.query('UPDATE users SET name = $1, email = $2 WHERE id = $3', [name, email, req.user.id]);
    res.json({ success: true, message: 'Profile updated' });
  } catch (error) {
    res.status(500).json({ error: 'Could not update profile' });
  }
});

module.exports = router;