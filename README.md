# CHC Paint Warehouse Sale 2026

## Deployment to Railway

1. Push this folder to a GitHub repo
2. Connect Railway to the repo
3. Deploy automatically

## Features

- 456 products across 12 brands
- Password protected (password: buyfromchc)
- 6 branch email routing
- Case quantity enforcement
- Promo system (per-case and multi-case)
- Credit application download
- Order submission via EmailJS

## EmailJS Configuration

Update these values in index.html:
- EMAILJS_CONFIG.publicKey
- EMAILJS_CONFIG.serviceId  
- EMAILJS_CONFIG.templateId

## Template Variables for EmailJS

- {{shop_name}} - Shop name
- {{contact_name}} - Contact person
- {{phone}} - Phone number
- {{customer_email}} - Email
- {{address}} - Delivery address
- {{branch}} - Selected branch
- {{order_id}} - Order ID
- {{order_items_html}} - HTML table with items (use triple braces {{{order_items_html}}})
- {{order_total}} - Order total
- {{order_count}} - Item count
- {{order_notes}} - Customer notes
