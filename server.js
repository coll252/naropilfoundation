/**
 * Naropil Children Foundation - Backend API
 * Architecture: Node.js, Express, MySQL, JWT, M-Pesa Integration
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const helmet = require('helmet');

const app = express();

// ==========================================
// 1. MIDDLEWARE & SECURITY
// ==========================================
app.use(helmet()); // Security headers
app.use(cors({ origin: process.env.FRONTEND_URL || '*' })); // Allow frontend origin
app.use(express.json()); // Parse JSON bodies
app.use(express.urlencoded({ extended: true }));

// ==========================================
// 2. DATABASE CONNECTION POOL
// ==========================================
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test DB Connection
pool.getConnection()
    .then(conn => {
        console.log('✅ Connected to MySQL Database');
        conn.release();
    })
    .catch(err => console.error('❌ Database connection failed:', err.message));

// ==========================================
// 3. AUTHENTICATION MIDDLEWARE
// ==========================================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
        req.user = user;
        next();
    });
};

const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin privileges required.' });
    next();
};

// ==========================================
// 4. M-PESA HELPER FUNCTIONS
// ==========================================
const getMpesaToken = async (req, res, next) => {
    const consumerKey = process.env.MPESA_CONSUMER_KEY;
    const consumerSecret = process.env.MPESA_CONSUMER_SECRET;
    const auth = Buffer.from(`${consumerKey}:${consumerSecret}`).toString('base64');
    const url = process.env.MPESA_ENVIRONMENT === 'sandbox' 
        ? 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'
        : 'https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials';

    try {
        const response = await axios.get(url, {
            headers: { Authorization: `Basic ${auth}` }
        });
        req.mpesaToken = response.data.access_token;
        next();
    } catch (error) {
        console.error('M-Pesa Token Error:', error.response?.data || error.message);
        res.status(500).json({ error: 'Failed to authenticate with M-Pesa.' });
    }
};

// ==========================================
// 5. API ROUTES
// ==========================================

// --- AUTHENTICATION ---
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) return res.status(400).json({ error: 'Invalid credentials' });

        const user = rows[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Invalid credentials' });

        const token = jwt.sign(
            { id: user.id, role: user.role, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );
        res.json({ message: 'Login successful', token, user: { id: user.id, username: user.username, role: user.role } });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// --- PUBLIC ROUTES (Forms) ---
app.post('/api/messages', async (req, res) => {
    const { name, email, subject, message } = req.body;
    try {
        await pool.query('INSERT INTO messages (name, email, subject, message) VALUES (?, ?, ?, ?)', [name, email, subject, message]);
        res.status(201).json({ message: 'Message sent successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/volunteers', async (req, res) => {
    const { name, email, phone, message } = req.body;
    try {
        await pool.query('INSERT INTO volunteers (name, email, phone, message) VALUES (?, ?, ?, ?)', [name, email, phone, message]);
        res.status(201).json({ message: 'Volunteer application submitted' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// --- M-PESA PAYMENTS (STK PUSH) ---
app.post('/api/mpesa/stkpush', getMpesaToken, async (req, res) => {
    const { phone, amount, name } = req.body; // Phone should be format 2547XXXXXXXX
    
    // Format phone number to 254...
    let formattedPhone = phone;
    if (phone.startsWith('0')) formattedPhone = `254${phone.slice(1)}`;
    if (phone.startsWith('+')) formattedPhone = phone.slice(1);

    const shortCode = process.env.MPESA_SHORTCODE;
    const passkey = process.env.MPESA_PASSKEY;
    
    // Generate Timestamp YYYYMMDDHHmmss
    const date = new Date();
    const timestamp = date.getFullYear() +
        ("0" + (date.getMonth() + 1)).slice(-2) +
        ("0" + date.getDate()).slice(-2) +
        ("0" + date.getHours()).slice(-2) +
        ("0" + date.getMinutes()).slice(-2) +
        ("0" + date.getSeconds()).slice(-2);
        
    const password = Buffer.from(shortCode + passkey + timestamp).toString('base64');
    
    const url = process.env.MPESA_ENVIRONMENT === 'sandbox'
        ? 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest'
        : 'https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest';

    try {
        const response = await axios.post(url, {
            BusinessShortCode: shortCode,
            Password: password,
            Timestamp: timestamp,
            TransactionType: 'CustomerPayBillOnline',
            Amount: amount,
            PartyA: formattedPhone,
            PartyB: shortCode,
            PhoneNumber: formattedPhone,
            CallBackURL: process.env.MPESA_CALLBACK_URL,
            AccountReference: 'Naropil Donation',
            TransactionDesc: 'Donation to Naropil Children Foundation'
        }, {
            headers: { Authorization: `Bearer ${req.mpesaToken}` }
        });

        // Save pending transaction to DB
        await pool.query(
            'INSERT INTO donations (name, phone, amount, merchant_request_id, checkout_request_id, status) VALUES (?, ?, ?, ?, ?, ?)',
            [name, formattedPhone, amount, response.data.MerchantRequestID, response.data.CheckoutRequestID, 'pending']
        );

        res.json({ message: 'STK Push sent to your phone. Please enter your PIN.', data: response.data });
    } catch (error) {
        console.error('STK Push Error:', error.response?.data || error.message);
        res.status(500).json({ error: 'Failed to initiate payment. Please check phone number format.' });
    }
});

// M-Pesa Callback (Webhook)
app.post('/api/mpesa/callback', async (req, res) => {
    try {
        const callbackData = req.body.Body.stkCallback;
        const checkoutRequestId = callbackData.CheckoutRequestID;
        const resultCode = callbackData.ResultCode;

        if (resultCode === 0) {
            // Success
            const items = callbackData.CallbackMetadata.Item;
            const receipt = items.find(item => item.Name === 'MpesaReceiptNumber').Value;
            
            await pool.query(
                'UPDATE donations SET status = ?, mpesa_receipt = ? WHERE checkout_request_id = ?',
                ['completed', receipt, checkoutRequestId]
            );
        } else {
            // Failed/Cancelled
            await pool.query(
                'UPDATE donations SET status = ? WHERE checkout_request_id = ?',
                ['failed', checkoutRequestId]
            );
        }
        res.status(200).send('OK'); // Safaricom expects a 200 response
    } catch (error) {
        console.error('Callback Error:', error);
        res.status(500).send('Error');
    }
});

// --- ADMIN SECURE ROUTES ---
app.get('/api/admin/dashboard', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const [donations] = await pool.query('SELECT SUM(amount) as total FROM donations WHERE status = "completed"');
        const [messages] = await pool.query('SELECT COUNT(*) as count FROM messages WHERE is_read = FALSE');
        const [recentDonations] = await pool.query('SELECT * FROM donations ORDER BY created_at DESC LIMIT 5');
        const [recentMessages] = await pool.query('SELECT * FROM messages ORDER BY created_at DESC LIMIT 5');

        res.json({
            stats: {
                totalDonations: donations[0].total || 0,
                unreadMessages: messages[0].count || 0
            },
            recentDonations,
            recentMessages
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
// 6. SERVER INITIALIZATION
// ==========================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV}`);
});