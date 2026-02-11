const express = require('express');
const cors = require('cors');
const path = require('path');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const XLSX = require('xlsx');
const csv = require('csv-parser');
const { Readable } = require('stream');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-in-production';
const BCRYPT_ROUNDS = 12;

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

// File upload (10MB max, memory storage)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = [
      'text/csv',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/octet-stream'
    ];
    if (allowed.includes(file.mimetype) || file.originalname.match(/\.(csv|xlsx|xls)$/i)) {
      cb(null, true);
    } else {
      cb(new Error('Only CSV and Excel files are allowed'));
    }
  }
});

// Rate limiting (in-memory)
const authAttempts = new Map();
const RATE_LIMIT_WINDOW = 5 * 60 * 1000; // 5 minutes (reduced from 15)

function checkRateLimit(ip, maxAttempts = 20) {
  const now = Date.now();
  const attempts = authAttempts.get(ip) || [];
  const recent = attempts.filter(t => now - t < RATE_LIMIT_WINDOW);
  authAttempts.set(ip, recent);
  return recent.length < maxAttempts;
}

function recordAttempt(ip) {
  const attempts = authAttempts.get(ip) || [];
  attempts.push(Date.now());
  authAttempts.set(ip, attempts);
}

function clearRateLimit(ip) {
  authAttempts.delete(ip);
}

// ========================================
// JWT ADMIN AUTH MIDDLEWARE
// ========================================
async function authenticateAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    // Verify admin still exists and is active
    const { data: admin, error } = await supabase
      .from('admin_users')
      .select('id, email, role, name, is_active')
      .eq('id', decoded.adminId)
      .single();

    if (error || !admin || !admin.is_active) {
      return res.status(401).json({ error: 'Invalid or inactive admin account' });
    }

    req.admin = admin;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired. Please log in again.' });
    }
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function requireSuperAdmin(req, res, next) {
  if (req.admin.role !== 'super_admin') {
    return res.status(403).json({ error: 'Super admin access required' });
  }
  next();
}

// ========================================
// ADMIN AUTH ROUTES
// ========================================

// Register first admin (super_admin) or additional admins (requires super_admin auth)
app.post('/api/admin/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Email, password, and name are required' });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    // Check if any admins exist
    const { count, error: countError } = await supabase
      .from('admin_users')
      .select('*', { count: 'exact', head: true });

    console.log('Admin count check:', { count, countError });

    let role = 'admin';

    if (!count || count === 0) {
      // First admin registration — becomes super_admin
      role = 'super_admin';
    } else {
      // Subsequent registrations require super_admin auth
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Super admin authentication required to add new admins' });
      }

      try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        const { data: admin } = await supabase
          .from('admin_users')
          .select('role')
          .eq('id', decoded.adminId)
          .single();

        if (!admin || admin.role !== 'super_admin') {
          return res.status(403).json({ error: 'Only super admins can create new admin accounts' });
        }
      } catch (err) {
        return res.status(401).json({ error: 'Invalid authentication token' });
      }
    }

    // Check for duplicate email
    const { data: existing } = await supabase
      .from('admin_users')
      .select('id')
      .eq('email', email.toLowerCase())
      .single();

    if (existing) {
      return res.status(409).json({ error: 'An admin with this email already exists' });
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    const { data: newAdmin, error } = await supabase
      .from('admin_users')
      .insert({
        email: email.toLowerCase(),
        password_hash: passwordHash,
        role,
        name,
        is_active: true
      })
      .select('id, email, role, name')
      .single();

    if (error) {
      console.error('Admin registration error:', JSON.stringify(error, null, 2));
      return res.status(500).json({ error: 'Failed to create admin account: ' + (error.message || error.code || 'unknown error') });
    }

    const token = jwt.sign(
      { adminId: newAdmin.id, email: newAdmin.email, role: newAdmin.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    console.log(`Admin registered: ${newAdmin.email} (${role})`);
    res.json({ success: true, token, admin: newAdmin });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Admin login
app.post('/api/admin/auth/login', async (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;

  if (!checkRateLimit(ip, 20)) {
    return res.status(429).json({ error: 'Too many login attempts. Please wait 5 minutes.' });
  }

  recordAttempt(ip);

  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const { data: admin, error } = await supabase
      .from('admin_users')
      .select('*')
      .eq('email', email.toLowerCase())
      .single();

    if (error || !admin) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    if (!admin.is_active) {
      return res.status(401).json({ error: 'Account is disabled. Contact super admin.' });
    }

    const validPassword = await bcrypt.compare(password, admin.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Update last_login
    await supabase
      .from('admin_users')
      .update({ last_login: new Date().toISOString() })
      .eq('id', admin.id);

    const token = jwt.sign(
      { adminId: admin.id, email: admin.email, role: admin.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Clear rate limit on successful login
    clearRateLimit(ip);

    console.log(`Admin login: ${admin.email}`);
    res.json({
      success: true,
      token,
      admin: { id: admin.id, email: admin.email, role: admin.role, name: admin.name }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Verify admin token
app.get('/api/admin/auth/me', authenticateAdmin, (req, res) => {
  res.json({ admin: req.admin });
});

// ========================================
// ADMIN USER MANAGEMENT
// ========================================
app.get('/api/admin/users', authenticateAdmin, requireSuperAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('admin_users')
      .select('id, email, role, name, is_active, last_login, created_at')
      .order('created_at', { ascending: true });

    if (error) throw error;
    res.json(data);
  } catch (error) {
    console.error('Fetch admins error:', error);
    res.status(500).json({ error: 'Failed to fetch admin users' });
  }
});

app.patch('/api/admin/users/:id', authenticateAdmin, requireSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { is_active, role } = req.body;

    // Prevent self-demotion
    if (id === req.admin.id && role && role !== 'super_admin') {
      return res.status(400).json({ error: 'Cannot demote yourself' });
    }

    const updates = {};
    if (typeof is_active === 'boolean') updates.is_active = is_active;
    if (role && ['super_admin', 'admin'].includes(role)) updates.role = role;

    const { data, error } = await supabase
      .from('admin_users')
      .update(updates)
      .eq('id', id)
      .select('id, email, role, name, is_active')
      .single();

    if (error) throw error;
    res.json(data);
  } catch (error) {
    console.error('Update admin error:', error);
    res.status(500).json({ error: 'Failed to update admin user' });
  }
});

// ========================================
// ADMIN SALES MANAGEMENT
// ========================================
app.get('/api/admin/sales', authenticateAdmin, async (req, res) => {
  try {
    const { data: sales, error } = await supabase
      .from('sales')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;

    // Add product counts and order counts for each sale
    const enriched = await Promise.all(sales.map(async (sale) => {
      const [{ count: productCount }, { count: orderCount }] = await Promise.all([
        supabase.from('products').select('*', { count: 'exact', head: true }).eq('sale_id', sale.id),
        supabase.from('orders').select('*', { count: 'exact', head: true }).eq('sale_id', sale.id)
      ]);
      return { ...sale, product_count: productCount || 0, order_count: orderCount || 0 };
    }));

    res.json(enriched);
  } catch (error) {
    console.error('Fetch sales error:', error);
    res.status(500).json({ error: 'Failed to fetch sales' });
  }
});

app.post('/api/admin/sales', authenticateAdmin, async (req, res) => {
  try {
    const { name, slug, description, password, status, start_date, end_date } = req.body;

    if (!name || !slug || !password) {
      return res.status(400).json({ error: 'Name, slug, and password are required' });
    }

    // Validate slug format
    if (!/^[a-z0-9-]+$/.test(slug)) {
      return res.status(400).json({ error: 'Slug must contain only lowercase letters, numbers, and hyphens' });
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    const { data, error } = await supabase
      .from('sales')
      .insert({
        name,
        slug,
        description: description || '',
        password_hash: passwordHash,
        status: status || 'draft',
        start_date: start_date || null,
        end_date: end_date || null,
        created_by: req.admin.id
      })
      .select()
      .single();

    if (error) {
      if (error.code === '23505') {
        return res.status(409).json({ error: 'A sale with this slug already exists' });
      }
      throw error;
    }

    console.log(`Sale created: ${name} by ${req.admin.email}`);
    res.json(data);
  } catch (error) {
    console.error('Create sale error:', error);
    res.status(500).json({ error: 'Failed to create sale' });
  }
});

app.get('/api/admin/sales/:id', authenticateAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('sales')
      .select('*')
      .eq('id', req.params.id)
      .single();

    if (error || !data) return res.status(404).json({ error: 'Sale not found' });
    res.json(data);
  } catch (error) {
    console.error('Fetch sale error:', error);
    res.status(500).json({ error: 'Failed to fetch sale' });
  }
});

app.patch('/api/admin/sales/:id', authenticateAdmin, async (req, res) => {
  try {
    const { name, description, status, start_date, end_date, password } = req.body;
    const updates = {};

    if (name) updates.name = name;
    if (description !== undefined) updates.description = description;
    if (status && ['draft', 'active', 'archived'].includes(status)) updates.status = status;
    if (start_date !== undefined) updates.start_date = start_date;
    if (end_date !== undefined) updates.end_date = end_date;
    if (password) updates.password_hash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    const { data, error } = await supabase
      .from('sales')
      .update(updates)
      .eq('id', req.params.id)
      .select()
      .single();

    if (error) throw error;
    res.json(data);
  } catch (error) {
    console.error('Update sale error:', error);
    res.status(500).json({ error: 'Failed to update sale' });
  }
});

app.delete('/api/admin/sales/:id', authenticateAdmin, requireSuperAdmin, async (req, res) => {
  try {
    // Soft delete — archive the sale
    const { data, error } = await supabase
      .from('sales')
      .update({ status: 'archived' })
      .eq('id', req.params.id)
      .select()
      .single();

    if (error) throw error;
    res.json({ success: true, sale: data });
  } catch (error) {
    console.error('Delete sale error:', error);
    res.status(500).json({ error: 'Failed to archive sale' });
  }
});

// ========================================
// ADMIN PRODUCT MANAGEMENT
// ========================================
app.get('/api/admin/sales/:saleId/products', authenticateAdmin, async (req, res) => {
  try {
    const { brand, category, search } = req.query;
    let query = supabase
      .from('products')
      .select('*')
      .eq('sale_id', req.params.saleId)
      .order('brand')
      .order('category')
      .order('name');

    if (brand) query = query.eq('brand', brand);
    if (category) query = query.eq('category', category);
    if (search) query = query.or(`sku.ilike.%${search}%,name.ilike.%${search}%`);

    const { data, error } = await query;
    if (error) throw error;
    res.json(data);
  } catch (error) {
    console.error('Fetch products error:', error);
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

app.post('/api/admin/sales/:saleId/products', authenticateAdmin, async (req, res) => {
  try {
    const { sku, brand, category, name, previous_price, sale_price, promo } = req.body;

    if (!sku || !brand || !name || !previous_price || !sale_price) {
      return res.status(400).json({ error: 'SKU, brand, name, previous_price, and sale_price are required' });
    }

    const { data, error } = await supabase
      .from('products')
      .insert({
        sale_id: req.params.saleId,
        sku,
        brand,
        category: category || '',
        name,
        previous_price: parseFloat(previous_price),
        sale_price: parseFloat(sale_price),
        promo: promo || null
      })
      .select()
      .single();

    if (error) {
      if (error.code === '23505') {
        return res.status(409).json({ error: 'A product with this SKU already exists in this sale' });
      }
      throw error;
    }

    res.json(data);
  } catch (error) {
    console.error('Create product error:', error);
    res.status(500).json({ error: 'Failed to create product' });
  }
});

// Bulk upload products via CSV or Excel
app.post('/api/admin/sales/:saleId/products/upload', authenticateAdmin, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    // Verify sale exists
    const { data: sale, error: saleError } = await supabase
      .from('sales')
      .select('id')
      .eq('id', req.params.saleId)
      .single();

    if (saleError || !sale) {
      return res.status(404).json({ error: 'Sale not found' });
    }

    let rows = [];
    const fileName = req.file.originalname.toLowerCase();

    if (fileName.endsWith('.xlsx') || fileName.endsWith('.xls')) {
      // Parse Excel
      const workbook = XLSX.read(req.file.buffer, { type: 'buffer' });
      const sheetName = workbook.SheetNames[0];
      const sheet = workbook.Sheets[sheetName];
      rows = XLSX.utils.sheet_to_json(sheet, { defval: '' });
    } else {
      // Parse CSV
      rows = await new Promise((resolve, reject) => {
        const results = [];
        const stream = Readable.from(req.file.buffer.toString());
        stream
          .pipe(csv())
          .on('data', (data) => results.push(data))
          .on('end', () => resolve(results))
          .on('error', reject);
      });
    }

    if (rows.length === 0) {
      return res.status(400).json({ error: 'File is empty or has no data rows' });
    }

    // Normalize column headers (case-insensitive)
    const normalizeKey = (key) => {
      const k = key.toLowerCase().trim().replace(/\s+/g, '_');
      const aliases = {
        'sku': 'sku', 'sku_code': 'sku', 'product_code': 'sku', 'item_code': 'sku',
        'brand': 'brand', 'manufacturer': 'brand',
        'category': 'category', 'cat': 'category', 'product_category': 'category',
        'name': 'name', 'description': 'name', 'product_name': 'name', 'product_description': 'name',
        'previous_price': 'previous_price', 'previousprice': 'previous_price', 'original_price': 'previous_price',
        'regular_price': 'previous_price', 'msrp': 'previous_price', 'ae_price': 'previous_price',
        'sale_price': 'sale_price', 'saleprice': 'sale_price', 'price': 'sale_price',
        'promo': 'promo', 'promotion': 'promo', 'promo_text': 'promo', 'special': 'promo'
      };
      return aliases[k] || k;
    };

    // Process and validate rows
    const results = { added: 0, updated: 0, failed: [] };
    const products = [];

    for (let i = 0; i < rows.length; i++) {
      const raw = rows[i];
      const row = {};
      Object.entries(raw).forEach(([key, value]) => {
        row[normalizeKey(key)] = typeof value === 'string' ? value.trim() : value;
      });

      // Validate required fields
      if (!row.sku || !row.brand || !row.name) {
        results.failed.push({ row: i + 2, reason: 'Missing sku, brand, or name', data: raw });
        continue;
      }

      const prevPrice = parseFloat(row.previous_price);
      const salePrice = parseFloat(row.sale_price);

      if (isNaN(prevPrice) || isNaN(salePrice) || prevPrice < 0 || salePrice < 0) {
        results.failed.push({ row: i + 2, reason: 'Invalid price values', data: raw });
        continue;
      }

      products.push({
        sale_id: req.params.saleId,
        sku: row.sku,
        brand: row.brand,
        category: row.category || '',
        name: row.name,
        previous_price: prevPrice,
        sale_price: salePrice,
        promo: row.promo || null
      });
    }

    // Upsert products in batches of 100
    for (let i = 0; i < products.length; i += 100) {
      const batch = products.slice(i, i + 100);
      const { data, error } = await supabase
        .from('products')
        .upsert(batch, { onConflict: 'sale_id,sku', ignoreDuplicates: false })
        .select();

      if (error) {
        console.error('Batch upsert error:', error);
        batch.forEach((p, idx) => {
          results.failed.push({ row: i + idx + 2, reason: error.message, data: p });
        });
      } else {
        // Count adds vs updates (approximate)
        results.added += data.length;
      }
    }

    console.log(`Product upload: ${results.added} added/updated, ${results.failed.length} failed by ${req.admin.email}`);
    res.json({
      success: true,
      total_rows: rows.length,
      added: results.added,
      failed: results.failed.length,
      failures: results.failed.slice(0, 20) // Return first 20 failures
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Failed to process file upload' });
  }
});

app.patch('/api/admin/sales/:saleId/products/:id', authenticateAdmin, async (req, res) => {
  try {
    const { sku, brand, category, name, previous_price, sale_price, promo } = req.body;
    const updates = {};

    if (sku) updates.sku = sku;
    if (brand) updates.brand = brand;
    if (category !== undefined) updates.category = category;
    if (name) updates.name = name;
    if (previous_price !== undefined) updates.previous_price = parseFloat(previous_price);
    if (sale_price !== undefined) updates.sale_price = parseFloat(sale_price);
    if (promo !== undefined) updates.promo = promo || null;

    const { data, error } = await supabase
      .from('products')
      .update(updates)
      .eq('id', req.params.id)
      .eq('sale_id', req.params.saleId)
      .select()
      .single();

    if (error) throw error;
    res.json(data);
  } catch (error) {
    console.error('Update product error:', error);
    res.status(500).json({ error: 'Failed to update product' });
  }
});

app.delete('/api/admin/sales/:saleId/products/:id', authenticateAdmin, async (req, res) => {
  try {
    const { error } = await supabase
      .from('products')
      .delete()
      .eq('id', req.params.id)
      .eq('sale_id', req.params.saleId);

    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    console.error('Delete product error:', error);
    res.status(500).json({ error: 'Failed to delete product' });
  }
});

// Delete all products for a sale
app.delete('/api/admin/sales/:saleId/products', authenticateAdmin, async (req, res) => {
  try {
    const { error } = await supabase
      .from('products')
      .delete()
      .eq('sale_id', req.params.saleId);

    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    console.error('Delete all products error:', error);
    res.status(500).json({ error: 'Failed to delete products' });
  }
});

// ========================================
// ADMIN ORDER MANAGEMENT
// ========================================
app.get('/api/admin/orders', authenticateAdmin, async (req, res) => {
  try {
    const { sale_id, status, branch, from_date, to_date } = req.query;
    let query = supabase
      .from('orders')
      .select('*')
      .order('created_at', { ascending: false });

    if (sale_id) query = query.eq('sale_id', sale_id);
    if (status) query = query.eq('status', status);
    if (branch) query = query.eq('branch', branch);
    if (from_date) query = query.gte('created_at', from_date);
    if (to_date) query = query.lte('created_at', to_date);

    const { data, error } = await query.limit(500);
    if (error) throw error;
    res.json(data);
  } catch (error) {
    console.error('Fetch orders error:', error);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

app.patch('/api/admin/orders/:id', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const validStatuses = ['pending', 'confirmed', 'shipped', 'delivered', 'cancelled'];

    if (!status || !validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status. Must be one of: ' + validStatuses.join(', ') });
    }

    const { data, error } = await supabase
      .from('orders')
      .update({ status })
      .eq('id', req.params.id)
      .select()
      .single();

    if (error) throw error;

    // Send status update email (non-blocking)
    if (transporter && data.email) {
      sendStatusUpdateEmail(data).catch(err => {
        console.error('Status email failed:', err.message);
      });
    }

    res.json(data);
  } catch (error) {
    console.error('Update order error:', error);
    res.status(500).json({ error: 'Failed to update order' });
  }
});

// Admin dashboard stats
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
  try {
    const [
      { count: totalSales },
      { count: activeSales },
      { count: totalOrders },
      { count: pendingOrders }
    ] = await Promise.all([
      supabase.from('sales').select('*', { count: 'exact', head: true }),
      supabase.from('sales').select('*', { count: 'exact', head: true }).eq('status', 'active'),
      supabase.from('orders').select('*', { count: 'exact', head: true }),
      supabase.from('orders').select('*', { count: 'exact', head: true }).eq('status', 'pending')
    ]);

    // Total revenue
    const { data: revenueData } = await supabase
      .from('orders')
      .select('total');

    const totalRevenue = (revenueData || []).reduce((sum, o) => sum + parseFloat(o.total || 0), 0);

    res.json({
      total_sales: totalSales || 0,
      active_sales: activeSales || 0,
      total_orders: totalOrders || 0,
      pending_orders: pendingOrders || 0,
      total_revenue: totalRevenue
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// ========================================
// CUSTOMER-FACING ROUTES (public)
// ========================================

// List active sales (for sale picker)
app.get('/api/sales', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('sales')
      .select('id, name, slug, description, status, start_date, end_date')
      .eq('status', 'active')
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data);
  } catch (error) {
    console.error('Fetch active sales error:', error);
    res.status(500).json({ error: 'Failed to fetch sales' });
  }
});

// Get products for a sale (grouped by brand + category)
app.get('/api/sales/:saleId/products', async (req, res) => {
  try {
    // Verify sale is active
    const { data: sale, error: saleError } = await supabase
      .from('sales')
      .select('id, status')
      .eq('id', req.params.saleId)
      .eq('status', 'active')
      .single();

    if (saleError || !sale) {
      return res.status(404).json({ error: 'Sale not found or not active' });
    }

    const { data: products, error } = await supabase
      .from('products')
      .select('*')
      .eq('sale_id', req.params.saleId)
      .order('brand')
      .order('category')
      .order('name');

    if (error) throw error;

    // Group products by brand → category (matching the existing frontend format)
    const grouped = {};
    const brands = [];
    const productCounts = {};

    products.forEach(p => {
      if (!grouped[p.brand]) {
        grouped[p.brand] = { hasCategories: false, categories: {}, products: [] };
        brands.push(p.brand);
        productCounts[p.brand] = 0;
      }
      productCounts[p.brand]++;

      if (p.category && p.category.trim() !== '') {
        grouped[p.brand].hasCategories = true;
        if (!grouped[p.brand].categories[p.category]) {
          grouped[p.brand].categories[p.category] = [];
        }
        grouped[p.brand].categories[p.category].push({
          sku: p.sku,
          name: p.name,
          previousPrice: p.previous_price.toString(),
          salePrice: p.sale_price.toString(),
          promo: p.promo || undefined
        });
      } else {
        grouped[p.brand].products.push({
          sku: p.sku,
          name: p.name,
          previousPrice: p.previous_price.toString(),
          salePrice: p.sale_price.toString(),
          promo: p.promo || undefined
        });
      }
    });

    // Clean up: brands with only flat products shouldn't have empty categories
    Object.values(grouped).forEach(brand => {
      if (!brand.hasCategories) {
        delete brand.categories;
      } else {
        delete brand.products;
      }
    });

    res.json({ products: grouped, brands, productCounts, total: products.length });
  } catch (error) {
    console.error('Fetch sale products error:', error);
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// Customer auth — verify sale password
app.post('/api/auth/verify', async (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;

  if (!checkRateLimit(ip, 10)) {
    return res.status(429).json({ error: 'Too many attempts. Please try again later.' });
  }

  recordAttempt(ip);

  try {
    const { sale_id, password } = req.body;

    if (!password) {
      return res.status(400).json({ error: 'Password required' });
    }

    // If sale_id provided, verify against sale password
    if (sale_id) {
      const { data: sale, error } = await supabase
        .from('sales')
        .select('id, password_hash, status')
        .eq('id', sale_id)
        .single();

      if (error || !sale) {
        return res.status(404).json({ error: 'Sale not found' });
      }

      if (sale.status !== 'active') {
        return res.status(403).json({ error: 'This sale is not currently active' });
      }

      const valid = await bcrypt.compare(password, sale.password_hash);
      if (valid) {
        console.log(`Customer auth success for sale ${sale_id} from ${ip}`);
        return res.json({ success: true });
      } else {
        console.log(`Customer auth failed for sale ${sale_id} from ${ip}`);
        return res.status(401).json({ error: 'Invalid password' });
      }
    }

    // Legacy fallback: verify against WAREHOUSE_PASSWORD env var
    const correctPassword = process.env.WAREHOUSE_PASSWORD;
    if (correctPassword && password === correctPassword) {
      return res.json({ success: true });
    }

    return res.status(401).json({ error: 'Invalid password' });
  } catch (error) {
    console.error('Auth verify error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
});

// Submit order (updated to include sale_id)
app.post('/api/orders', async (req, res) => {
  try {
    const { shopName, email, branch, items, total, sale_id } = req.body;

    if (!shopName || !email || !branch || !items || items.length === 0) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    if (!BRANCH_EMAILS[branch]) {
      return res.status(400).json({ error: 'Invalid branch' });
    }

    const orderCode = `ORD-${Date.now().toString(36).toUpperCase()}`;

    const orderData = {
      order_code: orderCode,
      shop_name: shopName,
      email,
      branch,
      items,
      total: parseFloat(total),
      status: 'pending'
    };

    if (sale_id) orderData.sale_id = sale_id;

    const { data, error } = await supabase
      .from('orders')
      .insert(orderData)
      .select()
      .single();

    if (error) {
      console.error('Supabase insert error:', error);
      return res.status(500).json({ error: 'Failed to save order' });
    }

    console.log('Order saved:', data.order_code);

    if (transporter) {
      sendOrderEmail(data).catch(err => {
        console.error('Email send failed:', err.message);
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

// ========================================
// EMAIL HELPERS
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

This order was submitted via the CHC Paint Warehouse Sale catalog.
    `.trim(),
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #1e293b; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
          <h1 style="margin: 0; font-size: 20px;">New Warehouse Sale Order</h1>
          <p style="margin: 5px 0 0; color: #94a3b8; font-size: 14px;">CHC Paint Warehouse Sale</p>
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

async function sendStatusUpdateEmail(order) {
  const statusLabels = {
    pending: 'Pending',
    confirmed: 'Confirmed',
    shipped: 'Shipped',
    delivered: 'Delivered',
    cancelled: 'Cancelled'
  };

  const mailOptions = {
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to: order.email,
    subject: `Order ${order.order_code} — Status Update: ${statusLabels[order.status] || order.status}`,
    text: `
Your order status has been updated.

Order ID: ${order.order_code}
New Status: ${statusLabels[order.status] || order.status}
Branch: ${order.branch}

If you have any questions, contact your CHC Paint branch.
    `.trim(),
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #1e293b; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
          <h1 style="margin: 0; font-size: 20px;">Order Status Update</h1>
        </div>
        <div style="border: 1px solid #e2e8f0; padding: 20px; border-radius: 0 0 8px 8px;">
          <p>Your order <strong>${order.order_code}</strong> has been updated to:</p>
          <div style="background: #f0fdf4; padding: 16px; border-radius: 8px; text-align: center; margin: 16px 0;">
            <span style="font-size: 24px; font-weight: bold; color: #16a34a;">${statusLabels[order.status] || order.status}</span>
          </div>
          <p style="color: #64748b; font-size: 14px;">If you have any questions, contact your CHC Paint ${order.branch} branch.</p>
        </div>
      </div>
    `
  };

  const result = await transporter.sendMail(mailOptions);
  console.log(`Status email sent to ${order.email} for ${order.order_code}`);
  return result;
}

// ========================================
// SERVE THE APP
// ========================================

// Admin panel route
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin', 'index.html'));
});

app.get('/admin/*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin', 'index.html'));
});

// Customer app (catch-all)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`CHC Warehouse Sale server running on port ${PORT}`);
  console.log(`Customer app: http://localhost:${PORT}`);
  console.log(`Admin panel: http://localhost:${PORT}/admin`);
  console.log(`Supabase connected: ${supabaseUrl}`);
  console.log(`Email notifications: ${transporter ? 'enabled' : 'disabled'}`);
});
