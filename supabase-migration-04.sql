-- ============================================
-- CHC Paint Warehouse Sale — Migration 04
-- Add notes column to orders table
-- Run this in Supabase SQL Editor
-- ============================================

ALTER TABLE orders ADD COLUMN IF NOT EXISTS notes TEXT;

SELECT 'Migration 04 complete — notes column added to orders' AS status;
