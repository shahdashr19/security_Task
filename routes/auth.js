const express = require('express');
const router = express.Router();

const {
  registerUser,
  loginUser,
  refreshToken,
  logoutUser
} = require('../controllers/authController');

const authenticateToken = require('../middlewares/authMiddleware');
const checkRole = require('../middlewares/roleMiddleware');

// ✅ Register
router.post('/register', registerUser);

// ✅ Login
router.post('/login', loginUser);

// ✅ Refresh Access Token
router.post('/refresh', refreshToken);

// ✅ Logout
router.post('/logout', logoutUser);

// ✅ Protected Route
router.get('/profile', authenticateToken, (req, res) => {
  res.json({
    message: 'User profile accessed',
    user: req.user
  });
});

// ✅ Admin Only Route
router.get('/admin', authenticateToken, checkRole('admin'), (req, res) => {
  res.json({ message: 'Welcome, admin 👑' });
});

module.exports = router;
