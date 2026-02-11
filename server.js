const express = require('express');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Store orders in memory (for production, use a database)
let orders = [];

// API endpoint to submit orders
app.post('/api/orders', (req, res) => {
  try {
    const { shopName, email, branch, items, total } = req.body;
    
    if (!shopName || !email || !branch || !items || items.length === 0) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const order = {
      id: `ORD-${Date.now()}`,
      shopName,
      email,
      branch,
      items,
      total,
      createdAt: new Date().toISOString(),
      status: 'pending'
    };

    orders.push(order);
    
    console.log('New order received:', order);
    console.log(`Order should be sent to: ${branch.toLowerCase()}@chcpaint.com`);

    res.json({ 
      success: true, 
      orderId: order.id,
      message: `Order submitted successfully to ${branch} branch`
    });
  } catch (error) {
    console.error('Order submission error:', error);
    res.status(500).json({ error: 'Failed to submit order' });
  }
});

// API endpoint to get all orders (for admin)
app.get('/api/orders', (req, res) => {
  res.json(orders);
});

// Serve the main app
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`CHC Warehouse Sale server running on port ${PORT}`);
  console.log(`Access the catalog at http://localhost:${PORT}`);
});
