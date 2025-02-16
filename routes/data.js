const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');

// Import the User model
const User = require('../models/User');

// Middleware to check if user is logged in
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        return next();
    } else {
        res.redirect('/auth/login');
    }
}

// Define a simple Data model (for user-specific data)
const DataSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    content: { type: String, required: true }
});

const Data = mongoose.model('Data', DataSchema);

// CREATE - Add new data
router.post('/add', isAuthenticated, async (req, res) => {
    try {
        const newData = new Data({
            userId: req.session.user._id,
            content: req.body.content
        });
        await newData.save();
        res.redirect('/dashboard');
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});

// READ - Get user's data
router.get('/', isAuthenticated, async (req, res) => {
    try {
        const userData = await Data.find({ userId: req.session.user._id });
        res.render('data', { user: req.session.user, data: userData });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});

// UPDATE - Edit user data
router.post('/edit/:id', isAuthenticated, async (req, res) => {
    try {
        await Data.findOneAndUpdate(
            { _id: req.params.id, userId: req.session.user._id },
            { content: req.body.content }
        );
        res.redirect('/data');
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});

// DELETE - Remove user data
router.post('/delete/:id', isAuthenticated, async (req, res) => {
    try {
        await Data.findOneAndDelete({ _id: req.params.id, userId: req.session.user._id });
        res.redirect('/data');
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});

module.exports = router;
