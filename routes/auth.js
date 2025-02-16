const express = require('express');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const nodemailer = require('nodemailer');
const path = require('path');
const User = require('../models/User');
const router = express.Router();
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const { body, validationResult } = require('express-validator');

// 🟢 Set up Multer for storing images
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/uploads/'); // Save to uploads folder
    },
    filename: (req, file, cb) => {
        cb(null, req.session.user._id + path.extname(file.originalname)); // Rename file to user ID
    }
});

const upload = multer({ storage });

// 🟢 Profile Picture Upload Route
router.post('/upload-profile', upload.single('profilePic'), async (req, res) => {
    if (!req.session.user) return res.redirect('/auth/login');

    try {
        const user = await User.findById(req.session.user._id);
        user.profilePic = req.file.filename; // Save filename in database
        await user.save();

        req.session.user.profilePic = user.profilePic; // Update session
        res.redirect('/dashboard');
    } catch (err) {
        console.error("Error uploading profile picture:", err);
        res.status(500).send("Server Error");
    }
});

// Render Registration Page
router.get('/register', (req, res) => {
    res.render('register', { error: null });
});

// Registration Route
router.post('/register', [
    body('username').notEmpty().withMessage('Username is required'),
    body('email').isEmail().withMessage('Invalid email format'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
], async (req, res) => {
    console.log("Received Registration Request:", req.body);

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.render('register', { error: errors.array()[0].msg });
    }

    try {
        let user = await User.findOne({ email: req.body.email });
        if (user) {
            console.log("User already exists:", user);
            return res.render('register', { error: 'Email is already in use' });
        }

        console.log("Hashing password...");
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(req.body.password, salt);
        console.log("Hashed Password:", hashedPassword);

        user = new User({
            username: req.body.username,
            email: req.body.email,
            password: hashedPassword
        });

        await user.save();
        console.log("User successfully saved:", user);

        res.redirect('/auth/login');
    } catch (err) {
        console.error("Error saving user:", err);
        res.status(500).send('Server Error');
    }
});



// Render Login Page
router.get('/login', (req, res) => {
    res.render('login', { error: null });
});

// Login Route

router.post('/login', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user) {
            return res.render('login', { error: 'Invalid email or password' });
        }

        const isMatch = await bcrypt.compare(req.body.password, user.password);
        if (!isMatch) {
            return res.render('login', { error: 'Invalid email or password' });
        }

        req.session.user = user;

        if (user.is2FAEnabled) {
            req.session.pending2FA = true; // 🟢 Require OTP verification
            return res.render('verify-otp', { email: user.email, error: null });
        }

        res.redirect('/dashboard');
    } catch (err) {
        console.error("Error during login:", err);
        res.status(500).send('Server Error');
    }
});




router.post('/verify-otp', async (req, res) => {
    if (!req.session.user || !req.session.pending2FA) {
        return res.redirect('/auth/login');
    }

    try {
        const user = await User.findById(req.session.user._id);
        if (!user || !user.twoFASecret) {
            return res.render('verify-otp', { error: 'Invalid session, please log in again.' });
        }

        const otp = req.body.otp;
        const isValid = speakeasy.totp.verify({
            secret: user.twoFASecret,
            encoding: 'base32',
            token: otp
        });

        if (isValid) {
            console.log(`✅ OTP verified successfully for ${user.email}`);
            req.session.pending2FA = false;  // ✅ Clear pending2FA flag
            res.redirect('/dashboard');
        } else {
            console.error(`❌ Invalid OTP for ${user.email}. Entered: ${otp}`);
            res.render('verify-otp', { error: 'Invalid OTP, please try again.' });
        }
    } catch (err) {
        console.error("Error verifying OTP:", err);
        res.status(500).send('Server Error');
    }
});













require('dotenv').config();
// 🟢 Configure Nodemailer
const transporter = nodemailer.createTransport({
    host: "smtp.mail.ru",  // 🟢 Correct Mail.ru SMTP server
    port: 465,             // 🟢 Use 465 (SSL) or 587 (TLS)
    secure: true,          // 🟢 Must be true for SSL
    auth: {
        user: process.env.EMAIL_USER,  // 🟢 Your Mail.ru email
        pass: process.env.EMAIL_PASS   // 🟢 Your Mail.ru App Password
    },
    tls: {
        rejectUnauthorized: false // 🟢 Prevent SSL issues
    }
});

// 🟢 Render Forgot Password Page
router.get('/forgot-password', (req, res) => {
    res.render('forgot-password', { error: null, success: null });
});

// 🟢 Handle New Password Submission
router.post('/reset-password/:token', async (req, res) => {
    try {
        const user = await User.findOne({ 
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.render('reset-password', { error: 'Invalid or expired reset link' });
        }

        // Hash New Password
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(req.body.password, salt);
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        res.redirect('/auth/login');
    } catch (err) {
        console.error(err);
        res.status(500).send("Server Error");
    }
});




// 🟢 Render Reset Password Page
router.get('/reset-password/:token', async (req, res) => {
    try {
        const user = await User.findOne({ 
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.render('reset-password', { error: 'Invalid or expired reset link' });
        }

        res.render('reset-password', { token: req.params.token, error: null });
    } catch (err) {
        console.error(err);
        res.status(500).send("Server Error");
    }
});




// 🟢 Request Password Reset (Send Email)
router.post('/forgot-password', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user) {
            return res.render('forgot-password', { error: 'Email not found', success: null });
        }

        // Generate Reset Token
        const token = crypto.randomBytes(32).toString('hex');
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour expiration
        await user.save();

        // Send Reset Email
        const resetLink = `${req.protocol}://${req.get('host')}/auth/reset-password/${token}`;
        const mailOptions = {
            from: 'gsosayanbek@mail.ru',  // Your email address (Mail.ru)
            to: user.email,
            subject: 'Password Reset Request',
            text: `Click the link below to reset your password:\n\n${resetLink}`
        };

        await transporter.sendMail(mailOptions);
        res.render('forgot-password', { success: 'Check your email for a reset link', error: null });
    } catch (err) {
        console.error("Error sending reset email:", err);
        res.render('forgot-password', { error: 'An error occurred. Please try again later.', success: null });
    }
});

// Route to display the 2FA setup page
router.get('/setup-2fa', async (req, res) => {
    if (!req.session.user) return res.redirect('/auth/login');

    const secret = speakeasy.generateSecret({
        length: 20,
        name: `MyApp (${req.session.user.email})`, // Display email in Authy
    });

    try {
        let user = await User.findById(req.session.user._id);
        user.twoFASecret = secret.base32;
        user.is2FAEnabled = false; // Set it to false until OTP is verified
        await user.save();

        req.session.user.twoFASecret = user.twoFASecret; // Update session

        // Generate the QR Code and ask for OTP immediately
        qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
            if (err) {
                console.error('QR Code Generation Error:', err);
                return res.status(500).send('Error generating QR code');
            }
            res.render('setup-2fa', { qrCode: data_url, showOTPInput: true, error: null });
        });
    } catch (err) {
        console.error('Error setting up 2FA:', err);
        res.status(500).send('Error setting up 2FA');
    }
});



// POST route for enabling 2FA
router.post('/enable-2fa', async (req, res) => {
    if (!req.session.user) return res.redirect('/auth/login');

    try {
        const user = await User.findById(req.session.user._id);
        if (!user || !user.twoFASecret) {
            return res.render('setup-2fa', { error: 'Invalid session, please log in again.', qrCode: req.session.qrCode });
        }

        const { otp } = req.body; // OTP entered by the user
        const isValid = speakeasy.totp.verify({
            secret: user.twoFASecret,
            encoding: 'base32',
            token: otp
        });

        if (isValid) {
            user.is2FAEnabled = true;
            await user.save();

            req.session.user.is2FAEnabled = true; // ✅ Update session
            res.redirect('/dashboard'); // Redirect after successful setup
        } else {
            res.render('setup-2fa', { error: 'Invalid OTP, please try again.', qrCode: req.session.qrCode });
        }
    } catch (err) {
        console.error("Error enabling 2FA:", err);
        res.status(500).send("Server Error");
    }
});





// Logout Route
router.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).send('Logout failed');
        res.redirect('/auth/login');
    });
});

module.exports = router;
