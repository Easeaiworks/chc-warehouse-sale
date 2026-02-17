-- ============================================
-- CHC Paint Warehouse Sale — FRESH MIGRATION
-- Run this in Supabase SQL Editor (paste all, click Run)
-- Safe to run multiple times (uses IF NOT EXISTS)
-- ============================================

-- 0. Create the updated_at trigger function (if not exists)
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 1. Admin Users Table
CREATE TABLE IF NOT EXISTS admin_users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('super_admin', 'admin')),
  name TEXT NOT NULL,
  is_active BOOLEAN DEFAULT true,
  last_login TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 2. Sales Table
CREATE TABLE IF NOT EXISTS sales (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  description TEXT,
  password_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'archived')),
  start_date TIMESTAMP WITH TIME ZONE,
  end_date TIMESTAMP WITH TIME ZONE,
  created_by UUID REFERENCES admin_users(id),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 3. Products Table
CREATE TABLE IF NOT EXISTS products (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sale_id UUID NOT NULL REFERENCES sales(id) ON DELETE CASCADE,
  sku TEXT NOT NULL,
  brand TEXT NOT NULL,
  category TEXT DEFAULT '',
  name TEXT NOT NULL,
  previous_price DECIMAL(10, 2) NOT NULL,
  sale_price DECIMAL(10, 2) NOT NULL,
  promo TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 4. Orders Table (if not exists)
CREATE TABLE IF NOT EXISTS orders (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  order_code TEXT UNIQUE NOT NULL,
  shop_name TEXT NOT NULL,
  email TEXT NOT NULL,
  branch TEXT NOT NULL,
  items JSONB NOT NULL DEFAULT '[]',
  total DECIMAL(10,2) DEFAULT 0,
  status TEXT DEFAULT 'pending',
  sale_id UUID REFERENCES sales(id),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 5. Add sale_id to orders if missing
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'orders' AND column_name = 'sale_id'
  ) THEN
    ALTER TABLE orders ADD COLUMN sale_id UUID REFERENCES sales(id);
  END IF;
END $$;

-- 6. Create indexes (safe with IF NOT EXISTS)
CREATE INDEX IF NOT EXISTS admin_users_email_idx ON admin_users(email);
CREATE INDEX IF NOT EXISTS sales_status_idx ON sales(status);
CREATE INDEX IF NOT EXISTS sales_slug_idx ON sales(slug);
CREATE INDEX IF NOT EXISTS products_sale_id_idx ON products(sale_id);
CREATE INDEX IF NOT EXISTS products_brand_idx ON products(brand);
CREATE UNIQUE INDEX IF NOT EXISTS products_sale_sku_idx ON products(sale_id, sku);
CREATE INDEX IF NOT EXISTS orders_sale_id_idx ON orders(sale_id);

-- 7. Disable RLS on all tables (service role key bypasses anyway)
ALTER TABLE admin_users DISABLE ROW LEVEL SECURITY;
ALTER TABLE sales DISABLE ROW LEVEL SECURITY;
ALTER TABLE products DISABLE ROW LEVEL SECURITY;
ALTER TABLE orders DISABLE ROW LEVEL SECURITY;

-- 8. Create triggers (drop first to avoid duplicates)
DROP TRIGGER IF EXISTS update_admin_users_updated_at ON admin_users;
CREATE TRIGGER update_admin_users_updated_at
  BEFORE UPDATE ON admin_users FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_sales_updated_at ON sales;
CREATE TRIGGER update_sales_updated_at
  BEFORE UPDATE ON sales FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_products_updated_at ON products;
CREATE TRIGGER update_products_updated_at
  BEFORE UPDATE ON products FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_orders_updated_at ON orders;
CREATE TRIGGER update_orders_updated_at
  BEFORE UPDATE ON orders FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- 9. Verify — this should show all 4 tables
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;
