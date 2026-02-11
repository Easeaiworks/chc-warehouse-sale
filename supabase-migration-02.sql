-- ============================================
-- CHC Paint Warehouse Sale - Migration 02
-- Admin Dashboard, Multi-Sale Support
-- Run this in Supabase SQL Editor
-- ============================================

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

CREATE INDEX IF NOT EXISTS admin_users_email_idx ON admin_users(email);
CREATE INDEX IF NOT EXISTS admin_users_role_idx ON admin_users(role);

ALTER TABLE admin_users ENABLE ROW LEVEL SECURITY;

CREATE POLICY "service_role_all_admin_users" ON admin_users
  FOR ALL TO service_role USING (true) WITH CHECK (true);

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

CREATE INDEX IF NOT EXISTS sales_status_idx ON sales(status);
CREATE INDEX IF NOT EXISTS sales_slug_idx ON sales(slug);

ALTER TABLE sales ENABLE ROW LEVEL SECURITY;

CREATE POLICY "service_role_all_sales" ON sales
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- 3. Products Table (database-driven catalog)
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

CREATE INDEX IF NOT EXISTS products_sale_id_idx ON products(sale_id);
CREATE INDEX IF NOT EXISTS products_brand_idx ON products(brand);
CREATE INDEX IF NOT EXISTS products_sku_idx ON products(sku);
CREATE UNIQUE INDEX IF NOT EXISTS products_sale_sku_idx ON products(sale_id, sku);

ALTER TABLE products ENABLE ROW LEVEL SECURITY;

CREATE POLICY "service_role_all_products" ON products
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- 4. Add sale_id to existing orders table
ALTER TABLE orders ADD COLUMN IF NOT EXISTS sale_id UUID REFERENCES sales(id);
CREATE INDEX IF NOT EXISTS orders_sale_id_idx ON orders(sale_id);

-- 5. Auto-update triggers for new tables
CREATE TRIGGER update_admin_users_updated_at
  BEFORE UPDATE ON admin_users
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_sales_updated_at
  BEFORE UPDATE ON sales
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_products_updated_at
  BEFORE UPDATE ON products
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- 6. Verify
SELECT 'Migration 02 complete!' AS status;
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;
