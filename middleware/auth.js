const express = require('express');
const router = express.Router();
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
const axios = require('axios');
require('dotenv').config();

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ── SEND OTP ─────────────────────────────────────────────
// POST /api/auth/send-otp
router.post('/send-otp', async (req, res) => {
  try {
    const { phone } = req.body;

    if (!phone || phone.length !== 10) {
      return res.status(400).json({ error: 'Enter a valid 10-digit phone number.' });
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Save OTP to database (hashed or plain — plain ok for now)
    await supabase
      .from('otps')
      .upsert({ phone, otp, expires_at: expiresAt.toISOString() }, { onConflict: 'phone' });

    // Send OTP via 2Factor.in (voice call on free tier)
    try {
      await axios.get(
        `https://2factor.in/API/V1/${process.env.TWOFACTOR_API_KEY}/SMS/${phone}/${otp}/OTP1`
      );
    } catch (smsError) {
      console.error('SMS send failed:', smsError.message);
      // Don't expose SMS failure to client
      // OTP is still saved in DB — useful for testing
    }

    // ✅ SECURITY FIX — OTP is NOT returned in response
    // It only goes to the user's phone via SMS
    return res.json({
      success: true,
      message: 'OTP sent to your phone number.'
    });

  } catch (error) {
    console.error('Send OTP error:', error.message);
    return res.status(500).json({ error: 'Failed to send OTP. Try again.' });
  }
});

// ── VERIFY OTP ────────────────────────────────────────────
// POST /api/auth/verify-otp
router.post('/verify-otp', async (req, res) => {
  try {
    const { phone, otp } = req.body;

    if (!phone || !otp) {
      return res.status(400).json({ error: 'Phone and OTP are required.' });
    }

    // Get OTP from DB
    const { data: otpRecord, error } = await supabase
      .from('otps')
      .select('*')
      .eq('phone', phone)
      .single();

    if (error || !otpRecord) {
      return res.status(400).json({ error: 'OTP not found. Request a new one.' });
    }

    // Check expiry
    if (new Date() > new Date(otpRecord.expires_at)) {
      await supabase.from('otps').delete().eq('phone', phone);
      return res.status(400).json({ error: 'OTP expired. Request a new one.' });
    }

    // Check OTP match
    if (otpRecord.otp !== otp.toString()) {
      return res.status(400).json({ error: 'Wrong OTP. Try again.' });
    }

    // OTP valid — delete it (one time use)
    await supabase.from('otps').delete().eq('phone', phone);

    // Get or create user
    let { data: user } = await supabase
      .from('users')
      .select('*')
      .eq('phone', phone)
      .single();

    if (!user) {
      const { data: newUser } = await supabase
        .from('users')
        .insert({ phone, role: 'customer' })
        .select()
        .single();
      user = newUser;
    }

    // Generate JWT
    const token = jwt.sign(
      {
        id:       user.id,
        phone:    user.phone,
        role:     user.role || 'customer',
        store_id: user.store_id || null,
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '30d' }
    );

    return res.json({
      success: true,
      token,
      user: {
        id:    user.id,
        phone: user.phone,
        role:  user.role || 'customer',
      }
    });

  } catch (error) {
    console.error('Verify OTP error:', error.message);
    return res.status(500).json({ error: 'Verification failed. Try again.' });
  }
});

// ── BIOMETRIC LOGIN ───────────────────────────────────────
// POST /api/auth/biometric
router.post('/biometric', async (req, res) => {
  try {
    const { phone } = req.body;

    if (!phone) {
      return res.status(400).json({ error: 'Phone required.' });
    }

    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('phone', phone)
      .single();

    if (error || !user) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const token = jwt.sign(
      {
        id:       user.id,
        phone:    user.phone,
        role:     user.role || 'customer',
        store_id: user.store_id || null,
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '30d' }
    );

    return res.json({
      success: true,
      token,
      user: {
        id:    user.id,
        phone: user.phone,
        role:  user.role || 'customer',
      }
    });

  } catch (error) {
    console.error('Biometric login error:', error.message);
    return res.status(500).json({ error: 'Biometric login failed.' });
  }
});

module.exports = router;