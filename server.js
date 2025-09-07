require('dotenv').config();
const { ObjectId } = require('mongoose').Types;
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
const PORT = 3000;

app.use(cors({
    origin: ['http://127.0.0.1:5500', 'http://localhost:5500', 'http://127.0.0.1:5501'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type','Authorization','X-Requested-With']
}));
app.use(bodyParser.json());
app.use(cookieParser());



const mongoURI = process.env.MONGO_URI;

mongoose.connect(mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.log('MongoDB connection error:', err));

// Email configuration
const transporter = nodemailer.createTransport({
    service: 'gmail', // Use 'gmail' service (auto-configures host/port)
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
    tls: {
        rejectUnauthorized: false // Bypass SSL certificate validation (for testing)
    }
});

// Test SMTP connection on server startup
transporter.verify((error, success) => {
    if (error) {
        console.error('SMTP Connection Error:', error);
    } else {
        console.log('SMTP Server is ready to send emails');
    }
});

// Function to send order confirmation email
async function sendOrderConfirmationEmail(order) {
    try {
        const mailOptions = {
            from: process.env.SMTP_FROM,
            to: order.customerEmail,
            subject: `Your Order Confirmation #${order._id}`,
            html: `
                    <h1>Thank you for your order!</h1>
                    <p>Hello ${order.customerName},</p>
                    <p>Your order has been received and is being processed.</p>
                    
                    <h2>Order Details</h2>
                    <p><strong>Order ID:</strong> ${order._id}</p>
                    <p><strong>Order Date:</strong> ${new Date(order.orderDate).toLocaleString()}</p>
                    <p><strong>Total Amount:</strong> ₹${order.totalAmount.toFixed(2)}</p>
                    <p><strong>Payment Method:</strong> ${order.paymentMethod}</p>
                    
                    <h3>Items Ordered</h3>
                    <ul>
                        ${order.products.map(item => `
                            <li>
                                ${item.name} - 
                                ₹${item.price.toFixed(2)} x 
                                ${item.quantity} = 
                                ₹${(item.price * item.quantity).toFixed(2)}
                            </li>
                        `).join('')}
                    </ul>
                    
                    <p>We'll notify you when your order ships.</p>
                    <p>Thank you for shopping with us!</p>
                `
        };

        await transporter.sendMail(mailOptions);
        console.log('Order confirmation email sent to:', order.customerEmail);
    } catch (error) {
        console.error('Error sending order confirmation email:', error);
    }
}

// Add this function near your other email functions
async function sendOtpEmail(email, otp, orderCode) {
    try {
        const mailOptions = {
            from: process.env.SMTP_FROM,
            to: email,
            subject: `Delivery OTP for Order #${orderCode}`,
            html: `
                <h2>Your OTP for Order Delivery</h2>
                <p>Your order is ready for delivery.</p>
                <p>Please provide the following OTP to the delivery person:</p>
                <h1 style="font-size: 32px; padding: 10px; background-color: #f0f0f0; text-align: center; letter-spacing: 5px;">${otp}</h1>
                <p>This OTP is valid for the next 30 minutes.</p>
                <p>Thank you for your order!</p>
            `
        };

        await transporter.sendMail(mailOptions);
        console.log('OTP email sent to:', email);
        return true;
    } catch (error) {
        console.error('Error sending OTP email:', error);
        return false;
    }
}

// Add a new endpoint for sending OTP
app.post('/api/orders/send-otp', async (req, res) => {
    try {
        const { orderId, customerEmail, orderCode } = req.body;

        // Generate a random 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        // Send the OTP via email
        const emailSent = await sendOtpEmail(customerEmail, otp, orderCode);

        if (emailSent) {
            res.status(200).json({
                success: true,
                message: 'OTP sent successfully',
                otp: otp // In a production app, you would store this securely
            });
        } else {
            res.status(500).json({
                success: false,
                message: 'Failed to send OTP'
            });
        }
    } catch (error) {
        console.error('Error in send-otp endpoint:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while sending OTP',
            error: error.message
        });
    }
});

const bcrypt = require('bcrypt');
const SALT_ROUNDS = 10;

const User = mongoose.model('User', new mongoose.Schema({
    fullname: String,
    email: String,
    password: String
}));

app.post('/api/register', async (req, res) => {
    try {
        const { fullname, email, password } = req.body;
        
        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered' });
        }
        
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        const user = new User({ fullname, email, password: hashedPassword });
        await user.save();
        
        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id, email: user.email },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '1h' }
        );
        
        // Set appropriate headers for CORS
        res.set('Access-Control-Allow-Origin', req.headers.origin);
        res.set('Access-Control-Allow-Credentials', 'true');
        
        res.status(201).json({
            message: 'User created successfully',
            user: {
                fullname: user.fullname,
                email: user.email
            },
            token: token
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: error.message || 'Registration failed' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id, email: user.email },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '1h' }
        );

        // Set appropriate headers for CORS
        res.set('Access-Control-Allow-Origin', req.headers.origin);
        res.set('Access-Control-Allow-Credentials', 'true');

        res.status(200).json({
            message: 'Login successful',
            user: {
                _id: user._id,
                fullname: user.fullname,
                email: user.email
            },
            token: token
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: error.message || 'Server error during login' });
    }
});

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

// Create uploads directory if it doesn't exist
const fs = require('fs');
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// Serve static files from uploads directory
app.use('/uploads', express.static('uploads'));

const Product = mongoose.model('Product', new mongoose.Schema({
    name: String,
    description: String,
    price: Number,
    stock: Number,
    image: String,
    storeId: { type: mongoose.Schema.Types.ObjectId, ref: 'Store' }
}));


// Product CRUD endpoints
app.get('/api/products', async (req, res) => {
    try {
        const { storeId } = req.query;
        let query = {};

        if (storeId) {
            query.storeId = storeId;
        }

        const products = await Product.find(query);
        res.json(products);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update your GET product endpoint
app.get('/api/products/:id', async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ error: 'Invalid product ID format' });
        }

        const product = await Product.findById(id);
        if (!product) {
            return res.status(404).json({ error: 'Product not found' });
        }
        res.json(product);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


// Update the POST endpoint for products
app.post('/api/products', upload.single('image'), async (req, res) => {
    try {
        const { name, description, price, stock, storeId } = req.body;

        // Validate required fields
        if (!name || !description || !price || !stock || !storeId) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Validate storeId format
        if (!ObjectId.isValid(storeId)) {
            return res.status(400).json({ error: 'Invalid store ID format' });
        }

        // Check if store exists
        const storeExists = await Store.findById(storeId);
        if (!storeExists) {
            return res.status(404).json({ error: 'Store not found' });
        }

        const imagePath = req.file ? '/uploads/' + req.file.filename : '';

        const product = new Product({
            name,
            description,
            price: Number(price),
            stock: Number(stock),
            image: imagePath,
            storeId
        });

        await product.save();
        res.status(201).json(product);
    } catch (error) {
        console.error('Error creating product:', error);
        res.status(500).json({
            error: 'Failed to create product',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});
app.put('/api/products/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const product = await Product.findByIdAndUpdate(id, req.body, { new: true });
        res.json(product);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/products/:id', async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        if (!product) return res.status(404).json({ error: 'Product not found' });

        // Delete the associated image file
        if (product.image) {
            const imagePath = path.join(__dirname, product.image);
            fs.unlink(imagePath, (err) => {
                if (err) console.error('Error deleting image:', err);
            });
        }

        await Product.findByIdAndDelete(req.params.id);
        res.json({ message: 'Product deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


const Store = mongoose.model('Store', new mongoose.Schema({
    seller: String,
    storeName: { type: String, unique: true },
    storeAddress: String,
    taxId: String,
    gstNumber: String,
    description: String,
    logoImage: String,
    storeUrl: { type: String, unique: true },
    createdAt: { type: Date, default: Date.now }
}));

// Add this with your other endpoints
app.post('/api/upload', upload.single('image'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        res.json({
            imageUrl: `/uploads/${req.file.filename}`
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Store creation endpoint
app.post('/api/stores', async (req, res) => {
    try {
        const { seller, storeName, storeAddress, taxId, gstNumber, description, logoImage } = req.body;

        // Basic validation
        if (!seller || !storeName || !storeAddress || !taxId || !gstNumber) {
            return res.status(400).json({ error: 'All required fields must be provided' });
        }

        // Additional validation for tax ID and GST number
        if (!/^\d{10}$/.test(taxId)) {
            return res.status(400).json({ error: 'Tax ID must be 10 digits' });
        }

        if (!/^\d{15}$/.test(gstNumber)) {
            return res.status(400).json({ error: 'GST Number must be 15 digits' });
        }

        // Check for existing store with same name
        const existingStore = await Store.findOne({
            $or: [
                { storeName },
                { storeUrl: storeName.toLowerCase().replace(/\s+/g, '-') }
            ]
        });

        if (existingStore) {
            return res.status(400).json({ error: 'Store name already exists. Please choose a different name.' });
        }

        const store = new Store({
            seller,
            storeName,
            storeAddress,
            taxId,
            gstNumber,
            description,
            logoImage,
            storeUrl: storeName.toLowerCase().replace(/\s+/g, '-')
        });

        await store.save();

        res.status(201).json({
            message: 'Store created successfully',
            store: {
                id: store._id,
                seller: store.seller,
                storeName: store.storeName,
                storeAddress: store.storeAddress,
                description: store.description,
                logoImage: store.logoImage
            }
        });
    } catch (error) {
        if (error.code === 11000) {
            return res.status(400).json({ error: 'Store name already exists. Please choose a different name.' });
        }
        res.status(500).json({ error: error.message });
    }
});

// Get latest store (move this before the :id route)
app.get('/api/stores/latest', async (req, res) => {
    try {
        const store = await Store.findOne().sort({ createdAt: -1 });
        if (!store) {
            return res.status(404).json({ error: 'No stores found' });
        }
        res.json({
            id: store._id,
            seller: store.seller,
            storeName: store.storeName,
            storeAddress: store.storeAddress,
            description: store.description,
            logoImage: store.logoImage
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Keep these routes in this order
app.get('/api/stores/:id', async (req, res) => {
    try {
        const store = await Store.findById(req.params.id);
        if (!store) {
            return res.status(404).json({ error: 'Store not found' });
        }
        res.json(store);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/stores/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const updates = req.body;

        const store = await Store.findByIdAndUpdate(id, updates, { new: true });
        if (!store) {
            return res.status(404).json({ error: 'Store not found' });
        }

        res.json({
            id: store._id,
            storeName: store.storeName,
            description: store.description,
            logoImage: store.logoImage
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/stores/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const store = await Store.findByIdAndDelete(id);
        if (!store) {
            return res.status(404).json({ error: 'Store not found' });
        }
        res.json({ message: 'Store deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get all stores
app.get('/api/stores', async (req, res) => {
    try {
        const { sellerId } = req.query;
        let query = {};

        if (sellerId) {
            query.seller = sellerId;
        }

        const stores = await Store.find(query, {
            storeName: 1,
            description: 1,
            logoImage: 1,
            createdAt: 1
        }).sort({ createdAt: -1 });

        res.json(stores);
    } catch (error) {
        console.error('Error fetching stores:', error);
        res.status(500).json({
            error: 'Failed to fetch stores',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

app.get('/api/stores/check-name', async (req, res) => {
    try {
        const { name } = req.query;
        if (!name) {
            return res.status(400).json({ error: 'Name parameter is required' });
        }

        const existingStore = await Store.findOne({
            $or: [
                { storeName: name },
                { storeUrl: name.toLowerCase().replace(/\s+/g, '-') }
            ]
        });

        res.json({ exists: !!existingStore });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Add this with your other models
const Order = mongoose.model('Order', new mongoose.Schema({
    products: [{
        productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
        name: String,
        price: Number,
        quantity: { type: Number, default: 1 }
    }],
    storeId: { type: mongoose.Schema.Types.ObjectId, ref: 'Store' },
    customerName: String,
    customerEmail: String,
    customerAddress: String,
    customerPhone: String,
    paymentMethod: String,
    orderDate: { type: Date, default: Date.now },
    status: { type: String, default: 'Pending' },
    totalAmount: Number
}));


// Add this with your other endpoints
app.post('/api/orders', async (req, res) => {
    try {
        const { products, customerName, customerEmail, customerPhone, customerAddress, paymentMethod, totalAmount, storeId } = req.body;

        // Validate required fields
        const missingFields = [];
        if (!products || !products.length) missingFields.push('products');
        if (!customerName) missingFields.push('customerName');
        if (!customerEmail) missingFields.push('customerEmail');
        if (!customerAddress) missingFields.push('customerAddress');
        if (!customerPhone) missingFields.push('customerPhone');
        if (!paymentMethod) missingFields.push('paymentMethod');
        if (!totalAmount) missingFields.push('totalAmount');
        if (!storeId) missingFields.push('storeId');

        if (missingFields.length > 0) {
            return res.status(400).json({
                error: 'Missing required fields',
                missingFields
            });
        }

        // Validate email format
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(customerEmail)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        // Validate product IDs and quantities
        for (const product of products) {
            if (!ObjectId.isValid(product.productId)) {
                return res.status(400).json({ error: 'Invalid product ID format' });
            }
            if (product.quantity < 1) {
                return res.status(400).json({ error: 'Product quantity must be at least 1' });
            }
        }

        // Validate store ID
        if (!ObjectId.isValid(storeId)) {
            return res.status(400).json({ error: 'Invalid store ID format' });
        }

        // Check if store exists
        const storeExists = await Store.findById(storeId);
        if (!storeExists) {
            return res.status(404).json({ error: 'Store not found' });
        }

        // Check product availability
        for (const item of products) {
            const product = await Product.findById(item.productId);
            if (!product) {
                return res.status(404).json({
                    error: `Product not found: ${item.productName}`
                });
            }
            if (product.stock < item.quantity) {
                return res.status(400).json({
                    error: `Insufficient stock for ${item.productName}`
                });
            }
        }

        // Create the order
        const order = new Order({
            products: products.map(p => ({
                productId: p.productId,
                name: p.productName,
                price: p.price,
                quantity: p.quantity
            })),
            storeId,
            customerName: customerName.trim(),
            customerEmail: customerEmail.trim(),
            customerAddress: customerAddress.trim(),
            customerPhone: customerPhone.trim(),
            paymentMethod,
            totalAmount,
            status: 'Pending'
        });

        await order.save();

        // Update product stock levels
        for (const item of products) {
            await Product.findByIdAndUpdate(item.productId, {
                $inc: { stock: -item.quantity }
            });
        }
        sendOrderConfirmationEmail(order);

        res.status(201).json(order);
    } catch (error) {
        console.error('Error creating order:', error);
        res.status(500).json({
            error: 'Failed to create order',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

app.get('/api/orders', async (req, res) => {
    try {
        const { storeId, email } = req.query;
        let query = {};

        if (storeId) {
            query.storeId = storeId;
        }

        if (email) {
            query.customerEmail = email;
        }

        const orders = await Order.find(query)
            .sort({ orderDate: -1 })
            .populate('products.productId', 'name image price');

        res.json(orders);
    } catch (error) {
        console.error('Error in /api/orders:', error);
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/orders/:id', async (req, res) => {
    try {
        const order = await Order.findByIdAndUpdate(
            req.params.id,
            { status: req.body.status },
            { new: true }
        );
        res.json(order);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/orders/:id', async (req, res) => {
    try {
        const { id } = req.params;
        await Order.findByIdAndDelete(id);
        res.json({ message: 'Order deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Add this with your other models in server.js
const Seller = mongoose.model('Seller', new mongoose.Schema({
    fullname: String,
    email: { type: String, unique: true },
    password: String,
    createdAt: { type: Date, default: Date.now }
}));

// Seller Registration
app.post('/api/seller/register', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if email already exists
        const existingSeller = await Seller.findOne({ email });
        if (existingSeller) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        const seller = new Seller({ email, password });
        await seller.save();

        res.status(201).json({
            message: 'Seller registered successfully',
            seller: {
                id: seller._id,
                email: seller.email
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Seller Login
app.post('/api/seller/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const seller = await Seller.findOne({ email });

        if (!seller) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        if (seller.password !== password) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        res.status(200).json({
            message: 'Login successful',
            seller: {
                id: seller._id,
                email: seller.email
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error during login' });
    }
});

// Admin routes
const Admin = mongoose.model('Admin', new mongoose.Schema({
    email: { type: String, unique: true },
    password: String,
    fullname: String,
    role: { type: String, default: 'admin' },
    lastLogin: Date
}));

// Initialize default admin account if none exists
async function initializeDefaultAdmin() {
    try {
        const adminCount = await Admin.countDocuments();
        
        if (adminCount === 0) {
            const defaultEmail = 'admin@example.com';
            const defaultPassword = 'admin123';
            const hashedPassword = await bcrypt.hash(defaultPassword, SALT_ROUNDS);
            
            const admin = new Admin({
                email: defaultEmail,
                password: hashedPassword,
                fullname: 'System Administrator',
                role: 'superadmin'
            });
            
            await admin.save();
            console.log('Default admin account created:');
            console.log(`Email: ${defaultEmail}`);
            console.log(`Password: ${defaultPassword}`);
        }
    } catch (error) {
        console.error('Error initializing default admin:', error);
    }
}

// Call this function when server starts
initializeDefaultAdmin();

// Admin Auth Middleware
const adminAuth = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ error: 'Authentication required' });
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
        const admin = await Admin.findById(decoded.adminId);
        
        if (!admin) {
            return res.status(401).json({ error: 'Invalid token' });
        }
        
        req.admin = admin;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Authentication failed' });
    }
};

// Add this with your other admin routes
app.get('/api/admin/verify-token', adminAuth, (req, res) => {
    res.json({ valid: true });
});

// Admin Registration (Should be used only once or in a secure environment)
app.post('/api/admin/register', async (req, res) => {
    try {
        const { email, password, fullname } = req.body;
        
        // Check if admin already exists
        const existingAdmin = await Admin.findOne({ email });
        if (existingAdmin) {
            return res.status(400).json({ error: 'Admin already registered with this email' });
        }
        
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        const admin = new Admin({ 
            email, 
            password: hashedPassword, 
            fullname
        });
        
        await admin.save();
        
        res.status(201).json({
            message: 'Admin registered successfully',
            admin: {
                id: admin._id,
                email: admin.email,
                fullname: admin.fullname
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Admin Login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const admin = await Admin.findOne({ email });
        
        if (!admin) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        const passwordMatch = await bcrypt.compare(password, admin.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        // Update last login
        admin.lastLogin = new Date();
        await admin.save();
        
        // Generate JWT token
        const token = jwt.sign(
            { adminId: admin._id, email: admin.email, role: admin.role },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '8h' }
        );
        
        res.status(200).json({
            message: 'Login successful',
            admin: {
                id: admin._id,
                email: admin.email,
                fullname: admin.fullname,
                role: admin.role
            },
            token: token
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error during login' });
    }
});

// Get Dashboard Stats
app.get('/api/admin/stats', adminAuth, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const totalSellers = await Seller.countDocuments();
        const totalStores = await Store.countDocuments();
        const totalOrders = await Order.countDocuments();
        const totalProducts = await Product.countDocuments();
        
        // Get recent orders
        const recentOrders = await Order.find()
            .sort({ orderDate: -1 })
            .limit(5)
            .populate('storeId', 'storeName');
            
        // Get recent stores
        const recentStores = await Store.find()
            .sort({ createdAt: -1 })
            .limit(5);
        
        res.json({
            stats: {
                totalUsers,
                totalSellers,
                totalStores,
                totalOrders,
                totalProducts
            },
            recentOrders,
            recentStores
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get all users for admin
app.get('/api/admin/users', adminAuth, async (req, res) => {
    try {
        const { page = 1, limit = 10, search } = req.query;
        const skip = (page - 1) * limit;
        
        let query = {};
        if (search) {
            query = { 
                $or: [
                    { fullname: { $regex: search, $options: 'i' } },
                    { email: { $regex: search, $options: 'i' } }
                ] 
            };
        }
        
        const users = await User.find(query, { password: 0 })
            .sort({ _id: -1 })
            .skip(skip)
            .limit(parseInt(limit));
            
        const total = await User.countDocuments(query);
        
        res.json({
            users,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            total
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get all sellers for admin
app.get('/api/admin/sellers', adminAuth, async (req, res) => {
    try {
        const { page = 1, limit = 10, search } = req.query;
        const skip = (page - 1) * limit;
        
        let query = {};
        if (search) {
            query = { 
                $or: [
                    { fullname: { $regex: search, $options: 'i' } },
                    { email: { $regex: search, $options: 'i' } }
                ] 
            };
        }
        
        const sellers = await Seller.find(query, { password: 0 })
            .sort({ _id: -1 })
            .skip(skip)
            .limit(parseInt(limit));
            
        // Count stores for each seller
        const sellersWithStoreCounts = await Promise.all(sellers.map(async (seller) => {
            const storeCount = await Store.countDocuments({ seller: seller._id.toString() });
            return {
                ...seller._doc,
                storeCount
            };
        }));
        
        const total = await Seller.countDocuments(query);
        
        res.json({
            sellers: sellersWithStoreCounts,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            total
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get all stores for admin
app.get('/api/admin/stores', adminAuth, async (req, res) => {
    try {
        const { page = 1, limit = 10, search } = req.query;
        const skip = (page - 1) * limit;
        
        let query = {};
        if (search) {
            query = { 
                $or: [
                    { storeName: { $regex: search, $options: 'i' } },
                    { description: { $regex: search, $options: 'i' } }
                ] 
            };
        }
        
        const stores = await Store.find(query)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(parseInt(limit));
            
        // Count products for each store
        const storesWithProductCounts = await Promise.all(stores.map(async (store) => {
            const productCount = await Product.countDocuments({ storeId: store._id });
            return {
                ...store._doc,
                productCount
            };
        }));
        
        const total = await Store.countDocuments(query);
        
        res.json({
            stores: storesWithProductCounts,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            total
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Admin routes for products
app.get('/api/admin/products', adminAuth, async (req, res) => {
    try {
        const { page = 1, limit = 10, search } = req.query;
        const skip = (page - 1) * limit;
        
        let query = {};
        if (search) {
            query = { 
                $or: [
                    { name: { $regex: search, $options: 'i' } },
                    { description: { $regex: search, $options: 'i' } }
                ] 
            };
        }
        
        const products = await Product.find(query)
            .sort({ _id: -1 })
            .skip(skip)
            .limit(parseInt(limit))
            .populate('storeId', 'storeName');
            
        const total = await Product.countDocuments(query);
        
        res.json({
            products,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            total
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Admin routes for orders
app.get('/api/admin/orders', adminAuth, async (req, res) => {
    try {
        const { page = 1, limit = 10, search, status } = req.query;
        const skip = (page - 1) * limit;
        
        let query = {};
        
        if (search) {
            query = { 
                $or: [
                    { customerName: { $regex: search, $options: 'i' } },
                    { customerEmail: { $regex: search, $options: 'i' } }
                ] 
            };
        }
        
        if (status) {
            query.status = status;
        }
        
        const orders = await Order.find(query)
            .sort({ orderDate: -1 })
            .skip(skip)
            .limit(parseInt(limit))
            .populate('storeId', 'storeName');
            
        const total = await Order.countDocuments(query);
        
        res.json({
            orders,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            total
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Admin update store status
app.put('/api/admin/stores/:id/status', adminAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;
        
        if (!['active', 'inactive', 'suspended'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        
        const store = await Store.findByIdAndUpdate(
            id, 
            { status }, 
            { new: true }
        );
        
        if (!store) {
            return res.status(404).json({ error: 'Store not found' });
        }
        
        res.json(store);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Admin update user
app.put('/api/admin/users/:id', adminAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { fullname, email } = req.body;
        
        // Make sure password isn't updated through this endpoint
        const updates = { fullname, email };
        
        const user = await User.findByIdAndUpdate(
            id,
            updates,
            { new: true, select: '-password' }
        );
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Admin delete user
app.delete('/api/admin/users/:id', adminAuth, async (req, res) => {
    try {
        const { id } = req.params;
        
        const user = await User.findByIdAndDelete(id);
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Admin update seller
app.put('/api/admin/sellers/:id', adminAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { fullname, email } = req.body;
        
        // Make sure password isn't updated through this endpoint
        const updates = { fullname, email };
        
        const seller = await Seller.findByIdAndUpdate(
            id,
            updates,
            { new: true, select: '-password' }
        );
        
        if (!seller) {
            return res.status(404).json({ error: 'Seller not found' });
        }
        
        res.json(seller);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Admin delete seller
app.delete('/api/admin/sellers/:id', adminAuth, async (req, res) => {
    try {
        const { id } = req.params;
        
        // First check if seller has stores
        const storeCount = await Store.countDocuments({ seller: id });
        
        if (storeCount > 0) {
            return res.status(400).json({ 
                error: 'Cannot delete seller with existing stores. Delete stores first.' 
            });
        }
        
        const seller = await Seller.findByIdAndDelete(id);
        
        if (!seller) {
            return res.status(404).json({ error: 'Seller not found' });
        }
        
        res.json({ message: 'Seller deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Admin update settings
app.put('/api/admin/settings', adminAuth, async (req, res) => {
    try {
        const { id } = req.admin;
        const { fullname, email, currentPassword, newPassword } = req.body;
        
        const admin = await Admin.findById(id);
        
        if (!admin) {
            return res.status(404).json({ error: 'Admin not found' });
        }
        
        // If changing password
        if (currentPassword && newPassword) {
            const passwordMatch = await bcrypt.compare(currentPassword, admin.password);
            
            if (!passwordMatch) {
                return res.status(401).json({ error: 'Current password is incorrect' });
            }
            
            admin.password = await bcrypt.hash(newPassword, SALT_ROUNDS);
        }
        
        // Update other fields
        admin.fullname = fullname || admin.fullname;
        admin.email = email || admin.email;
        
        await admin.save();
        
        res.json({
            message: 'Settings updated successfully',
            admin: {
                id: admin._id,
                email: admin.email,
                fullname: admin.fullname
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Generate sales report
app.get('/api/admin/reports/sales', adminAuth, async (req, res) => {
    try {
        const { startDate, endDate } = req.query;
        
        let query = {};
        
        if (startDate && endDate) {
            query.orderDate = {
                $gte: new Date(startDate),
                $lte: new Date(endDate)
            };
        }
        
        const orders = await Order.find(query)
            .sort({ orderDate: -1 })
            .populate('storeId', 'storeName');
        
        // Calculate total sales
        const totalSales = orders.reduce((sum, order) => sum + order.totalAmount, 0);
        
        // Group by store
        const salesByStore = {};
        orders.forEach(order => {
            const storeName = order.storeId ? order.storeId.storeName : 'Unknown Store';
            if (!salesByStore[storeName]) {
                salesByStore[storeName] = {
                    totalAmount: 0,
                    orderCount: 0
                };
            }
            salesByStore[storeName].totalAmount += order.totalAmount;
            salesByStore[storeName].orderCount += 1;
        });
        
        res.json({
            totalOrders: orders.length,
            totalSales,
            salesByStore,
            orders
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Set up mongoose connection monitor
mongoose.connection.on('error', (err) => {
    console.error('MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
    console.warn('MongoDB disconnected, trying to reconnect...');
});

mongoose.connection.on('reconnected', () => {
    console.log('MongoDB reconnected');
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({
        error: 'Server error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    // Application specific logging, throwing an error, or other logic here
});