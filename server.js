const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// --- MIDDLEWARE ---
app.use(express.json());
app.use(cors());

// --- DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ Nexus Database Connected'))
    .catch(err => console.error('❌ DB Connection Error:', err));

// --- USER MODEL ---
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    balance: { type: Number, default: 0 },
    kycStatus: { type: String, default: 'unverified' }, // unverified, pending, verified
    isMerchant: { type: Boolean, default: false },
    investments: [{
        planName: String,
        amount: Number,
        apy: Number,
        startDate: { type: Date, default: Date.now },
        endDate: Date,
        status: { type: String, default: 'active' }
    }]
});

const User = mongoose.model('User', UserSchema);

// --- AUTH MIDDLEWARE ---
const protect = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) return res.status(401).json({ msg: 'No token, authorization denied' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (e) {
        res.status(400).json({ msg: 'Token is not valid' });
    }
};

// --- ROUTES ---

// 1. Register User
app.post('/api/auth/register', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        let user = await User.findOne({ email });
        if (user) return res.status(400).json({ msg: 'User already exists' });

        user = new User({ name, email, password });
        
        // Hash Password
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        
        await user.save();

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
    } catch (err) {
        res.status(500).send('Server error');
    }
});

// 2. Login User
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ msg: 'Invalid Credentials' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ msg: 'Invalid Credentials' });

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { id: user._id, name: user.name, balance: user.balance } });
    } catch (err) {
        res.status(500).send('Server error');
    }
});

// 3. Get User Data (For Dashboard)
app.get('/api/user/me', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (err) {
        res.status(500).send('Server error');
    }
});

// 4. Start Investment Plan (Wealth Engine)
app.post('/api/invest/start', protect, async (req, res) => {
    const { planName, amount, apy, durationDays } = req.body;
    try {
        const user = await User.findById(req.user.id);

        if (user.balance < amount) {
            return res.status(400).json({ msg: 'Insufficient funds in Nexus wallet' });
        }

        const endDate = new Date();
        endDate.setDate(endDate.getDate() + durationDays);

        // Deduct from balance & add to investments
        user.balance -= amount;
        user.investments.push({ planName, amount, apy, endDate });

        await user.save();
        res.json({ msg: 'Investment started!', balance: user.balance, investments: user.investments });
    } catch (err) {
        res.status(500).send('Server error');
    }
});

// 5. Merchant Application
app.post('/api/merchant/apply', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        
        // Check if they have the $500 security deposit
        if (user.balance < 500) {
            return res.status(400).json({ msg: 'Insufficient balance for security deposit ($500)' });
        }

        user.balance -= 500;
        user.isMerchant = true; // In real-world, set to 'pending' until manual review
        
        await user.save();
        res.json({ msg: 'Merchant status approved!', isMerchant: true });
    } catch (err) {
        res.status(500).send('Server error');
    }
});
// --- ADMIN MIDDLEWARE ---
const adminProtect = (req, res, next) => {
    const token = req.header('x-admin-token');
    if (!token) return res.status(401).json({ msg: 'No token, authorization denied' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.role !== 'admin') throw new Error();
        next();
    } catch (e) {
        res.status(400).json({ msg: 'Token is not valid' });
    }
};

// --- ADMIN ROUTES ---

// 1. Admin Login (Checks the hidden password)
app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    
    // Compare against the secret password stored in your .env file
    if (password === process.env.ADMIN_PASSWORD) {
        const adminToken = jwt.sign({ role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '12h' });
        res.json({ token: adminToken });
    } else {
        res.status(401).json({ msg: 'Access Denied: Invalid Admin Credentials' });
    }
});

// 2. Get Pending KYC Users
app.get('/api/admin/kyc-pending', adminProtect, async (req, res) => {
    try {
        // Fetch all users whose KYC status is 'pending'
        const users = await User.find({ kycStatus: 'pending' }).select('-password');
        res.json(users);
    } catch (err) {
        res.status(500).send('Server error');
    }
});

// 3. Approve or Reject KYC
app.post('/api/admin/kyc-action', adminProtect, async (req, res) => {
    const { userId, action } = req.body; // action will be 'approve' or 'reject'
    try {
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ msg: 'User not found' });

        if (action === 'approve') {
            user.kycStatus = 'verified';
        } else if (action === 'reject') {
            user.kycStatus = 'unverified';
        }

        await user.save();
        res.json({ msg: `User KYC ${action}d successfully` });
    } catch (err) {
        res.status(500).send('Server error');
    }
});

// 4. (Optional) Route for normal users to submit KYC and become 'pending'
app.post('/api/user/submit-kyc', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        user.kycStatus = 'pending';
        await user.save();
        res.json({ msg: 'KYC Submitted successfully' });
    } catch (err) {
        res.status(500).send('Server error');
    }
});
// --- SERVER START ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Nexus Backend running on port ${PORT}`));