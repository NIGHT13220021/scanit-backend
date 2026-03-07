const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const db = require('../db');
const axios = require('axios');

const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

const send2FactorOTP = async (phone, otp) => {
  const response = await axios.get(
  `https://2factor.in/API/V1/${process.env.TWOFACTOR_API_KEY}/SMS/${phone}/${otp}/AUTOGEN`
);
  console.log('2Factor response:', response.data);
  return response.data;
};

router.post('/send-otp', async (req, res) => {
  const { phone } = req.body;
  if (!phone || phone.length !== 10) {
    return res.status(400).json({ error: 'Valid 10-digit phone required' });
  }
  try {
    const otp = generateOTP();
    const expires = new Date(Date.now() + 10 * 60 * 1000);

    await db.query(
      `INSERT INTO otps (phone, otp, expires_at)
       VALUES ($1, $2, $3)
       ON CONFLICT (phone) DO UPDATE SET otp=$2, expires_at=$3, is_used=false`,
      [phone, otp, expires]
    );

    let smsSent = false;
    try {
      await send2FactorOTP(phone, otp);
      smsSent = true;
      console.log(`✅ OTP sent via 2Factor to ${phone}`);
    } catch (smsError) {
      console.log(`⚠️ SMS failed: ${smsError.message}`);
      console.log(`⚠️ Details: ${JSON.stringify(smsError.response?.data)}`);
      console.log(`📱 DEV OTP for ${phone}: ${otp}`);
    }

    res.json({
      success: true,
      message: smsSent ? 'OTP sent to your phone' : 'OTP ready',
      otp: process.env.NODE_ENV !== 'production' ? otp : undefined
    });

  } catch (error) {
    console.error('Send OTP error:', error);
    res.status(500).json({ error: 'Could not send OTP' });
  }
});

router.post('/verify-otp', async (req, res) => {
  const { phone, otp } = req.body;
  if (!phone || !otp) {
    return res.status(400).json({ error: 'Phone and OTP required' });
  }
  try {
    const result = await db.query(
      `SELECT * FROM otps 
       WHERE phone = $1 AND otp = $2 
       AND expires_at > NOW() AND is_used = false`,
      [phone, otp]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    await db.query(
      'UPDATE otps SET is_used = true WHERE phone = $1',
      [phone]
    );

    let user = await db.query(
      'SELECT * FROM users WHERE phone = $1',
      [phone]
    );

    if (user.rows.length === 0) {
      user = await db.query(
        'INSERT INTO users (phone) VALUES ($1) RETURNING *',
        [phone]
      );
    }

    const token = jwt.sign(
      { id: user.rows[0].id, phone },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '30d' }
    );

    res.json({ success: true, token, user: user.rows[0] });

  } catch (error) {
    console.error('Verify OTP error:', error);
    res.status(500).json({ error: 'Could not verify OTP' });
  }
});

module.exports = router;