-- ============================================
-- CHC Paint Warehouse Sale — Migration 03
-- Add case_qty column to products table
-- Run this in Supabase SQL Editor
-- ============================================

ALTER TABLE products ADD COLUMN IF NOT EXISTS case_qty INTEGER DEFAULT 1;

SELECT 'Migration 03 complete — case_qty column added' AS status;
