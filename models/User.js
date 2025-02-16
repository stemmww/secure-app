const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    profilePic: { type: String, default: "default.png" }, // 🟢 Store profile picture filename
    twoFASecret: { type: String }, // Store the 2FA secret key
    is2FAEnabled: {type: Boolean, default: false }// Flag to track if 2FA is enabled for the user
});

module.exports = mongoose.model('User', userSchema);
