const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'uniqueEcomSecret123!';

// Middleware
app.use(cors());
app.use(express.json());

app.use('/images', express.static(__dirname + '/images'));




// MongoDB Connection
mongoose.connect(process.env.MONGO_URI || 'mongodb+srv://ridwanshuvo38_db_user:H3nkKxPltWpeZoa6@unique-ecom.urfzpdx.mongodb.net/unique-ecom')
.then(() => console.log('MongoDB Connected Successfully!'))
.catch(err => console.error('MongoDB Connection Error:', err));

// MongoDB Schemas and Models
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
}, { timestamps: true });

const ProductSchema = new mongoose.Schema({
    name: { type: String, required: true },
    price: { type: Number, required: true },
    image: { type: String },
    description: { type: String },
    category: { type: String }
}, { timestamps: true });

const OrderItemSchema = new mongoose.Schema({
    product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    quantity: { type: Number, required: true },
    price: { type: Number, required: true }
});

const OrderSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    items: [OrderItemSchema],
    total: { type: Number, required: true },
    status: { type: String, default: 'pending' },
    shippingAddress: {
        name: { type: String, required: true },
        address: { type: String, required: true },
        city: { type: String, required: true },
        zip: { type: String, required: true }
    },
    paymentMethod: { type: String, required: true }
}, { timestamps: true });

// Create Models
const User = mongoose.model('User', UserSchema);
const Product = mongoose.model('Product', ProductSchema);
const Order = mongoose.model('Order', OrderSchema);

// Auth middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Routes

// Auth routes
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({ name, email, password: hashedPassword });
        
        const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
        
        res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
        
        res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Product routes
app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find();
        res.json(products);
    } catch (error) {
        console.error('Products error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/products/:id', async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        if (!product) {
            return res.status(404).json({ error: 'Product not found' });
        }
        res.json(product);
    } catch (error) {
        console.error('Product detail error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// FIXED: Simple order creation alternative - PROPER USER LINKING
app.post('/api/orders-simple', authenticateToken, async (req, res) => {
    try {
        const { items, shippingAddress, paymentMethod } = req.body;
        
        console.log('Received order data:', { 
            userFromToken: req.user.id,
            itemsCount: items.length,
            shippingAddress,
            paymentMethod 
        });

        // Validate user exists in database
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ 
                success: false,
                error: 'User not found. Please login again.' 
            });
        }

        console.log('Found user in database:', { 
            userId: user._id, 
            userName: user.name 
        });
        
        // Calculate total
        const total = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
        
        // Get all products to map IDs correctly
        const allProducts = await Product.find();
        
        const orderItems = await Promise.all(items.map(async (item) => {
            let productId;
            
            if (item.id) {
                const productById = allProducts.find(p => p._id.toString() === item.id);
                if (productById) {
                    productId = productById._id;
                    console.log(`Found product by ID: ${item.id} -> ${productById.name}`);
                }
            }
            
            if (!productId && item.name) {
                const productByName = allProducts.find(p => p.name === item.name);
                if (productByName) {
                    productId = productByName._id;
                    console.log(`Found product by name: ${item.name} -> ${productByName._id}`);
                }
            }
            
            if (!productId) {
                console.warn(`Product not found for item:`, item);
                productId = new mongoose.Types.ObjectId();
            }
            
            return {
                product: productId,
                quantity: item.quantity,
                price: item.price
            };
        }));
        
        console.log('Processed order items:', orderItems);
        
        // Create order with user ID from database
        const order = await Order.create({
            user: user._id,
            items: orderItems,
            total,
            shippingAddress,
            paymentMethod
        });

        console.log('Order created successfully:', { 
            orderId: order._id,
            userId: order.user,
            total: order.total
        });
        
        // Populate the order to return complete details
        const populatedOrder = await Order.findById(order._id)
            .populate('user', 'name email')
            .populate('items.product', 'name price image');
        
        res.status(201).json({
            success: true,
            order: {
                id: populatedOrder._id,
                user: populatedOrder.user ? {
                    id: populatedOrder.user._id,
                    name: populatedOrder.user.name,
                    email: populatedOrder.user.email
                } : null,
                items: populatedOrder.items.map(item => ({
                    product: item.product ? {
                        id: item.product._id,
                        name: item.product.name,
                        price: item.product.price,
                        image: item.product.image
                    } : { name: 'Product not found' },
                    quantity: item.quantity,
                    price: item.price,
                    subtotal: item.quantity * item.price
                })),
                total: populatedOrder.total,
                status: populatedOrder.status,
                shippingAddress: populatedOrder.shippingAddress,
                paymentMethod: populatedOrder.paymentMethod,
                createdAt: populatedOrder.createdAt
            }
        });
        
    } catch (error) {
        console.error('Order creation error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Order creation failed: ' + error.message 
        });
    }
});

app.get('/api/orders', authenticateToken, async (req, res) => {
    try {
        const orders = await Order.find({ user: req.user.id })
            .populate('items.product', 'name image price')
            .sort({ createdAt: -1 });
        
        res.json(orders);
    } catch (error) {
        console.error('Orders fetch error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Seed sample products
app.post('/api/seed-products', async (req, res) => {
    try {
        await Product.deleteMany({});
        
        const sampleProducts = [
            {
                name: "Wireless Bluetooth Headphones",
                price: 79.99,
                image: "/images/wireless-bluetooth.jpeg",
                description: "High-quality wireless headphones with noise cancellation.",
                category: "Electronics"
            },
            {
                name: "Smartphone",
                price: 599.99,
                image: "/images/smartphone.jpeg",
                description: "Latest smartphone with advanced features and camera.",
                category: "Electronics"
            },
            {
                name: "Laptop Backpack",
                price: 49.99,
                image: "/images/laptop-backpack.jpeg",
                description: "Durable backpack with laptop compartment and water resistance.",
                category: "Accessories"
            },
            {
                name: "Fitness Tracker",
                price: 129.99,
                image: "/images/fitness-tracker.jpeg",
                description: "Track your steps, heart rate, and sleep patterns.",
                category: "Electronics"
            },
            {
                name: "Coffee Maker",
                price: 89.99,
                image: "/images/coffee-maker.jpeg",
                description: "Programmable coffee maker with thermal carafe.",
                category: "Home"
            },
            {
                name: "Desk Lamp",
                price: 34.99,
                image: "/images/lamp.jpeg",
                description: "LED desk lamp with adjustable brightness.",
                category: "Home"
            }
        ];
        
        await Product.insertMany(sampleProducts);
        res.json({ message: 'Sample products added successfully!' });
    } catch (error) {
        console.error('Seed products error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Debug route to view all data
app.get('/api/debug/all-data', async (req, res) => {
    try {
        const users = await User.find({}, 'name email createdAt');
        const products = await Product.find({}, 'name price category');
        const orders = await Order.find({})
            .populate('user', 'name email')
            .populate('items.product', 'name price');
        
        res.json({
            users,
            products,
            orders: orders.map(order => ({
                id: order._id,
                total: order.total,
                status: order.status,
                customer: order.user ? order.user.name : 'No user',
                items: order.items.map(item => ({
                    product: item.product ? item.product.name : 'Product not found',
                    quantity: item.quantity,
                    price: item.price,
                    subtotal: item.quantity * item.price
                }))
            }))
        });
    } catch (error) {
        console.error('Debug data error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Health check route
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'Server is running',
        timestamp: new Date().toISOString()
    });
});

// Initialize server with sample data
async function startServer() {
    try {
        const productCount = await Product.countDocuments();
        if (productCount === 0) {
            console.log('Seeding sample products...');
            const sampleProducts = [
                {
                    name: "Wireless Bluetooth Headphones",
                    price: 79.99,
                    image: "backend/images/wireless-bluetooth.jpeg",
                    description: "High-quality wireless headphones with noise cancellation.",
                    category: "Electronics"
                },
                {
                    name: "Smartphone",
                    price: 599.99,
                    image: "/images/smartphone.jpeg",
                    description: "Latest smartphone with advanced features and camera.",
                    category: "Electronics"
                },
                {
                    name: "Laptop Backpack",
                    price: 49.99,
                    image: "/images/laptop backpack.jpeg",
                    description: "Durable backpack with laptop compartment and water resistance.",
                    category: "Accessories"
                },
                {
                    name: "Fitness Tracker",
                    price: 129.99,
                    image: "https://via.placeholder.com/300x200?text=Fitness+Tracker",
                    description: "Track your steps, heart rate, and sleep patterns.",
                    category: "Electronics"
                },
                {
                    name: "Coffee Maker",
                    price: 89.99,
                    image: "https://via.placeholder.com/300x200?text=Coffee+Maker",
                    description: "Programmable coffee maker with thermal carafe.",
                    category: "Home"
                },
                {
                    name: "Desk Lamp",
                    price: 34.99,
                    image: "https://via.placeholder.com/300x200?text=Desk+Lamp",
                    description: "LED desk lamp with adjustable brightness.",
                    category: "Home"
                }
            ];
            
            await Product.insertMany(sampleProducts);
            console.log('Sample products seeded successfully!');
        }
        
        app.listen(PORT, () => {
            console.log(`Server running on port ${PORT}`);
            console.log(`API Base URL: http://localhost:${PORT}/api`);
            console.log(`Health Check: http://localhost:${PORT}/api/health`);
            console.log(`Debug Data: http://localhost:${PORT}/api/debug/all-data`);
        });
    } catch (error) {
        console.error('Unable to start server:', error);
    }
}

startServer();