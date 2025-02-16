const express = require('express');
const router = express.Router();

// Middleware to check if user is logged in
function isAuthenticated(req, res, next) {
    if (req.session && req.session.user) {
        return next();
    } else {
        res.redirect('/auth/login');
    }
}
// Dashboard Route (Protected)
router.get('/', (req, res) => {
    if (!req.session.user) return res.redirect('/auth/login');

    // 🟢 Ensure 2FA is verified before allowing access
    if (req.session.user.is2FAEnabled && req.session.pending2FA) {
        return res.redirect('/auth/verify-otp');
    }

    res.render('dashboard', { user: req.session.user });
});


module.exports = router;
