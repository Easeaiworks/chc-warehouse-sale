-- ============================================
-- CHC Paint Warehouse Sale - Supabase Setup
-- Run this in Supabase SQL Editor
-- Dashboard → SQL Editor → New Query → Paste & Run
-- ============================================

-- 1. Create orders table
CREATE TABLE IF NOT EXISTS orders (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  order_code TEXT UNIQUE NOT NULL,
  shop_name TEXT NOT NULL,
  email TEXT NOT NULL,
  branch TEXT NOT NULL,
  items JSONB NOT NULL,
  total DECIMAL(10, 2) NOT NULL,
  status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'confirmed', 'shipped', 'delivered', 'cancelled')),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 2. Create indexes for performance
CREATE INDEX IF NOT EXISTS orders_branch_idx ON orders(branch);
CREATE INDEX IF NOT EXISTS orders_created_at_idx ON orders(created_at DESC);
CREATE INDEX IF NOT EXISTS orders_shop_name_idx ON orders(shop_name);
CREATE INDEX IF NOT EXISTS orders_status_idx ON orders(status);

-- 3. Enable Row Level Security
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;

-- 4. RLS Policy: Allow inserts via service role (backend server)
CREATE POLICY "service_role_insert_orders" ON orders
  FOR INSERT
  TO service_role
  WITH CHECK (true);

-- 5. RLS Policy: Allow reads via service role (backend server)
CREATE POLICY "service_role_select_orders" ON orders
  FOR SELECT
  TO service_role
  USING (true);

-- 6. RLS Policy: Allow updates via service role (backend server)
CREATE POLICY "service_role_update_orders" ON orders
  FOR UPDATE
  TO service_role
  USING (true);

-- 7. Auto-update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_orders_updated_at
  BEFORE UPDATE ON orders
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- 8. Verify setup
SELECT 'Orders table created successfully!' AS status;
SELECT column_name, data_type, is_nullable
FROM information_schema.columns
WHERE table_name = 'orders'
ORDER BY ordinal_position;
