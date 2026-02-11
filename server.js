const express = require('express');
const cors = require('cors');
const path = require('path');
const nodemailer = require('nodemailer');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ========================================
// SUPABASE CLIENT
// ========================================
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY;

if (!supabaseUrl || !supabaseServiceKey) {
  console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_KEY environment variables');
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseServiceKey);

// ========================================
// EMAIL CONFIGURATION
// ========================================
const BRANCH_EMAILS = {
  "Woodbridge": "woodbridge@chcpaint.com",
  "Markham": "markham@chcpaint.com",
  "Ottawa": "ottawa@chcpaint.com",
  "Hamilton": "hamilton@chcpaint.com",
  "Oakville": "oakville@chcpaint.com",
  "St. Catharines": "stcatharines@chcpaint.com"
};

let transporter = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
  console.log('Email transport configured');
} else {
  console.log('SMTP not configured — email notifications disabled');
}

// ========================================
// MIDDLEWARE
// ========================================
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Rate limiting for auth endpoint (simple in-memory)
const authAttempts = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const MAX_ATTEMPTS = 10;

function checkRateLimit(ip) {
  const now = Date.now();
  const attempts = authAttempts.get(ip) || [];
  const recentAttempts = attempts.filter(t => now - t < RATE_LIMIT_WINDOW);
  authAttempts.set(ip, recentAttempts);
  return recentAttempts.length < MAX_ATTEMPTS;
}

function recordAttempt(ip) {
  const attempts = authAttempts.get(ip) || [];
  attempts.push(Date.now());
  authAttempts.set(ip, attempts);
}

// ========================================
// AUTH ENDPOINT - Server-side password verification
// ========================================
app.post('/api/auth/verify', (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;

  if (!checkRateLimit(ip)) {
    return res.status(429).json({ error: 'Too many attempts. Please try again later.' });
  }

  recordAttempt(ip);

  const { password } = req.body;
  const correctPassword = process.env.WAREHOUSE_PASSWORD;

  if (!correctPassword) {
    console.error('WAREHOUSE_PASSWORD environment variable not set');
    return res.status(500).json({ error: 'Server configuration error' });
  }

  if (!password) {
    return res.status(400).json({ error: 'Password required' });
  }

  if (password === correctPassword) {
    console.log(`Successful auth from ${ip}`);
    res.json({ success: true });
  } else {
    console.log(`Failed auth attempt from ${ip}`);
    res.status(401).json({ error: 'Invalid password' });
  }
});

// ========================================
// ORDERS API - Supabase-backed
// ========================================

// Submit a new order
app.post('/api/orders', async (req, res) => {
  try {
    const { shopName, email, branch, items, total } = req.body;

    // Validate required fields
    if (!shopName || !email || !branch || !items || items.length === 0) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // Validate branch
    if (!BRANCH_EMAILS[branch]) {
      return res.status(400).json({ error: 'Invalid branch' });
    }

    const orderCode = `ORD-${Date.now().toString(36).toUpperCase()}`;

    // Insert into Supabase
    const { data, error } = await supabase
      .from('orders')
      .insert({
        order_code: orderCode,
        shop_name: shopName,
        email: email,
        branch: branch,
        items: items,
        total: parseFloat(total),
        status: 'pending'
      })
      .select()
      .single();

    if (error) {
      console.error('Supabase insert error:', error);
      return res.status(500).json({ error: 'Failed to save order' });
    }

    console.log('Order saved to Supabase:', data.id);

    // Send email notification (non-blocking)
    if (transporter) {
      sendOrderEmail(data).catch(err => {
        console.error('Email send failed (non-blocking):', err.message);
      });
    }

    res.json({
      success: true,
      orderId: data.order_code,
      message: `Order submitted successfully to ${branch} branch`
    });
  } catch (error) {
    console.error('Order submission error:', error);
    res.status(500).json({ error: 'Failed to submit order' });
  }
});

// Get all orders (admin endpoint)
app.get('/api/orders', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('orders')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) {
      console.error('Supabase select error:', error);
      return res.status(500).json({ error: 'Failed to fetch orders' });
    }

    res.json(data);
  } catch (error) {
    console.error('Orders fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// ========================================
// EMAIL HELPER
// ========================================
async function sendOrderEmail(order) {
  const branchEmail = BRANCH_EMAILS[order.branch];
  if (!branchEmail) return;

  const itemsList = order.items.map(item =>
    `  ${item.sku} - ${item.name} x${item.quantity} @ $${parseFloat(item.salePrice).toFixed(2)} = $${(parseFloat(item.salePrice) * item.quantity).toFixed(2)}`
  ).join('\n');

  const mailOptions = {
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to: branchEmail,
    cc: order.email,
    subject: `New Warehouse Sale Order - ${order.order_code} from ${order.shop_name}`,
    text: `
New Warehouse Sale Order
========================

Order ID: ${order.order_code}
Shop Name: ${order.shop_name}
Contact Email: ${order.email}
Branch: ${order.branch}
Date: ${new Date(order.created_at).toLocaleString()}

Items Ordered:
${itemsList}

Order Total: $${parseFloat(order.total).toFixed(2)}

This order was submitted via the CHC Paint Warehouse Sale 2026 catalog.
    `.trim(),
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #1e293b; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
          <h1 style="margin: 0; font-size: 20px;">New Warehouse Sale Order</h1>
          <p style="margin: 5px 0 0; color: #94a3b8; font-size: 14px;">CHC Paint Warehouse Sale 2026</p>
        </div>
        <div style="border: 1px solid #e2e8f0; padding: 20px; border-radius: 0 0 8px 8px;">
          <table style="width: 100%; border-collapse: collapse; margin-bottom: 16px;">
            <tr><td style="padding: 8px 0; color: #64748b; width: 140px;">Order ID</td><td style="padding: 8px 0; font-weight: bold;">${order.order_code}</td></tr>
            <tr><td style="padding: 8px 0; color: #64748b;">Shop Name</td><td style="padding: 8px 0; font-weight: bold;">${order.shop_name}</td></tr>
            <tr><td style="padding: 8px 0; color: #64748b;">Contact Email</td><td style="padding: 8px 0;">${order.email}</td></tr>
            <tr><td style="padding: 8px 0; color: #64748b;">Branch</td><td style="padding: 8px 0; font-weight: bold;">${order.branch}</td></tr>
          </table>
          <h3 style="border-bottom: 2px solid #f97316; padding-bottom: 8px; color: #1e293b;">Items Ordered</h3>
          <table style="width: 100%; border-collapse: collapse;">
            <thead>
              <tr style="background: #f8fafc;">
                <th style="text-align: left; padding: 8px; font-size: 12px; color: #64748b;">SKU</th>
                <th style="text-align: left; padding: 8px; font-size: 12px; color: #64748b;">Product</th>
                <th style="text-align: center; padding: 8px; font-size: 12px; color: #64748b;">Qty</th>
                <th style="text-align: right; padding: 8px; font-size: 12px; color: #64748b;">Price</th>
              </tr>
            </thead>
            <tbody>
              ${order.items.map(item => `
                <tr style="border-bottom: 1px solid #e2e8f0;">
                  <td style="padding: 8px; font-family: monospace; color: #2563eb; font-size: 13px;">${item.sku}</td>
                  <td style="padding: 8px; font-size: 13px;">${item.name}</td>
                  <td style="padding: 8px; text-align: center;">${item.quantity}</td>
                  <td style="padding: 8px; text-align: right; font-weight: bold; color: #16a34a;">$${(parseFloat(item.salePrice) * item.quantity).toFixed(2)}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
          <div style="background: #f0fdf4; padding: 16px; border-radius: 8px; margin-top: 16px; text-align: right;">
            <span style="font-size: 18px; font-weight: bold; color: #16a34a;">Total: $${parseFloat(order.total).toFixed(2)}</span>
          </div>
        </div>
      </div>
    `
  };

  const result = await transporter.sendMail(mailOptions);
  console.log(`Order email sent to ${branchEmail} for ${order.order_code}`);
  return result;
}

// ========================================
// SERVE THE APP
// ========================================
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`CHC Warehouse Sale server running on port ${PORT}`);
  console.log(`Access the catalog at http://localhost:${PORT}`);
  console.log(`Supabase connected: ${supabaseUrl}`);
  console.log(`Email notifications: ${transporter ? 'enabled' : 'disabled'}`);
});
