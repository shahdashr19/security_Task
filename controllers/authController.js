// controllers/authController.js (FINAL VERSION WITH BONUS)

const User = require('../models/User');
const TokenModel = require('../models/Token');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

// ✅ Register User
exports.registerUser = [
  body('name').notEmpty().withMessage('Name is required'),
  body('email').isEmail().withMessage('Valid email is required'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),

  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    try {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ message: 'Email already registered' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const newUser = new User({ name, email, password: hashedPassword });
      await newUser.save();

      res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server error' });
    }
  }
];

// ✅ Login User
exports.loginUser = [
  body('email').isEmail().withMessage('Enter a valid email'),
  body('password').notEmpty().withMessage('Password is required'),

  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
      const user = await User.findOne({ email });
      if (!user) return res.status(400).json({ message: 'Invalid credentials' });

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

      const accessToken = jwt.sign(
        { id: user._id, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '15m' }
      );

      const refreshToken = jwt.sign(
        { id: user._id },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: '7d' }
      );

      await TokenModel.create({ userId: user._id, token: refreshToken });

      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: false,
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000
      });

      res.status(200).json({ accessToken, message: 'Login successful' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server error' });
    }
  }
];

// ✅ Refresh Token with Rotation
exports.refreshToken = async (req, res) => {
  const oldToken = req.cookies.refreshToken;
  if (!oldToken) return res.status(401).json({ message: 'No refresh token' });

  try {
    const payload = jwt.verify(oldToken, process.env.JWT_REFRESH_SECRET);

    const tokenInDb = await TokenModel.findOne({ userId: payload.id, token: oldToken });
    if (!tokenInDb) return res.status(403).json({ message: 'Refresh token invalid or used' });

    await TokenModel.deleteOne({ _id: tokenInDb._id });

    const newRefreshToken = jwt.sign(
      { id: payload.id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: '7d' }
    );

    await TokenModel.create({ userId: payload.id, token: newRefreshToken });

    const newAccessToken = jwt.sign(
      { id: payload.id },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: false,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({ accessToken: newAccessToken });
  } catch (err) {
    console.error(err);
    res.status(403).json({ message: 'Invalid refresh token' });
  }
};

// ✅ Logout User
exports.logoutUser = async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(400).json({ message: 'No token found' });

  try {
    await TokenModel.deleteOne({ token });
    res.clearCookie('refreshToken', {
      httpOnly: true,
      sameSite: 'strict',
      secure: false
    });

    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Logout failed' });
  }
};