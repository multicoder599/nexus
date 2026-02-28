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

// ==========================================
// --- DATABASE MODELS ---
// ==========================================

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

// NEW: Transaction Model for tracking Deposits and Withdrawals
const transactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['deposit', 'withdrawal'], required: true },
    method: { type: String, required: true }, // e.g., 'Crypto (USDC)', 'Mobile Money'
    amount: { type: Number, required: true },
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});
const Transaction = mongoose.model('Transaction', transactionSchema);

// ==========================================
// --- AUTH MIDDLEWARE ---
// ==========================================

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

// ==========================================
// --- USER ROUTES ---
// ==========================================

// 1. Register User
app.post('/api/auth/register', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        let user = await User.findOne({ email });
        if (user) return res.status(400).json({ msg: 'User already exists' });

        user = new User({ name, email, password });
        
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

// 3. Get User Data
app.get('/api/user/me', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (err) {
        res.status(500).send('Server error');
    }
});

// 4. Submit KYC
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

// 5. Start Investment Plan
app.post('/api/invest/start', protect, async (req, res) => {
    const { planName, amount, apy, durationDays } = req.body;
    try {
        const user = await User.findById(req.user.id);

        if (user.balance < amount) {
            return res.status(400).json({ msg: 'Insufficient funds in Nexus wallet' });
        }

        const endDate = new Date();
        endDate.setDate(endDate.getDate() + durationDays);

        user.balance -= amount;
        user.investments.push({ planName, amount, apy, endDate });

        await user.save();
        res.json({ msg: 'Investment started!', balance: user.balance, investments: user.investments });
    } catch (err) {
        res.status(500).send('Server error');
    }
});

// 6. Merchant Application
app.post('/api/merchant/apply', protect, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (user.balance < 500) {
            return res.status(400).json({ msg: 'Insufficient balance for security deposit ($500)' });
        }
        user.balance -= 500;
        user.isMerchant = true; 
        await user.save();
        res.json({ msg: 'Merchant status approved!', isMerchant: true });
    } catch (err) {
        res.status(500).send('Server error');
    }
});

// 7. Request a Deposit (NEW)
app.post('/api/finance/deposit', protect, async (req, res) => {
    const { amount, method } = req.body;
    try {
        if (!amount || amount <= 0) {
            return res.status(400).json({ msg: 'Invalid amount' });
        }

        const transaction = new Transaction({
            userId: req.user.id,
            type: 'deposit',
            method: method || 'Crypto',
            amount: amount,
            status: 'pending'
        });

        await transaction.save();
        res.json({ msg: 'Deposit request submitted. Waiting for admin approval.', transactionId: transaction._id });
    } catch (err) {
        res.status(500).send('Server error');
    }
});
// 8. Request a Withdrawal (NEW)
app.post('/api/finance/withdraw', protect, async (req, res) => {
    const { amount, method } = req.body;
    try {
        if (!amount || amount <= 0) {
            return res.status(400).json({ msg: 'Invalid amount' });
        }

        const user = await User.findById(req.user.id);
        
        // Check if they have enough balance
        if (user.balance < amount) {
            return res.status(400).json({ msg: 'Insufficient funds' });
        }

        // Deduct the balance immediately
        user.balance -= amount;
        await user.save();

        // Create a transaction record
        const transaction = new Transaction({
            userId: req.user.id,
            type: 'withdrawal',
            method: method || 'Crypto',
            amount: amount,
            status: 'pending' // Admin can review this later
        });

        await transaction.save();
        res.json({ msg: 'Withdrawal requested successfully', balance: user.balance, transactionId: transaction._id });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});
// ==========================================
// --- ADMIN ROUTES ---
// ==========================================

// 1. Admin Login
app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
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
        const users = await User.find({ kycStatus: 'pending' }).select('-password');
        res.json(users);
    } catch (err) {
        res.status(500).send('Server error');
    }
});

// 3. Approve or Reject KYC
app.post('/api/admin/kyc-action', adminProtect, async (req, res) => {
    const { userId, action } = req.body; 
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

// 4. Get Pending Deposits (NEW)
app.get('/api/admin/pending-deposits', adminProtect, async (req, res) => {
    try {
        const deposits = await Transaction.find({ type: 'deposit', status: 'pending' }).populate('userId', 'name email');
        res.json(deposits);
    } catch (err) {
        res.status(500).send('Server error');
    }
});

// 5. Approve or Reject Deposit (NEW)
app.post('/api/admin/action-deposit', adminProtect, async (req, res) => {
    const { transactionId, action } = req.body; 
    try {
        const transaction = await Transaction.findById(transactionId);
        if (!transaction) return res.status(404).json({ msg: 'Transaction not found' });
        if (transaction.status !== 'pending') return res.status(400).json({ msg: 'Transaction already processed' });

        if (action === 'approve') {
            transaction.status = 'approved';
            // Add money to the user's balance
            const user = await User.findById(transaction.userId);
            if(user) {
                user.balance += transaction.amount;
                await user.save();
            }
        } else if (action === 'reject') {
            transaction.status = 'rejected';
        }

        await transaction.save();
        res.json({ msg: `Deposit ${action}d successfully` });
    } catch (err) {
        res.status(500).send('Server error');
    }
});

// --- SERVER START ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Nexus Backend running on port ${PORT}`));