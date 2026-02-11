# CHC Paint - Warehouse Sale 2026

Password-protected product catalog for CHC Paint's warehouse sale.

## Features

- 🔐 Password-protected access (password: `buyfromchc`)
- 📦 428 products across 10 brands
- 🏷️ Categories for 3M, SEM, PPG, and Norton
- 🛒 Shopping cart functionality
- 📧 Branch-specific email routing for orders
- 📱 Mobile responsive design

## Branch Email Routing

Orders are routed to the selected branch:
- Woodbridge → woodbridge@chcpaint.com
- Markham → markham@chcpaint.com
- Ottawa → ottawa@chcpaint.com
- Hamilton → hamilton@chcpaint.com
- Oakville → oakville@chcpaint.com
- St. Catharines → stcatharines@chcpaint.com

---

## Deploy to Railway

### Option 1: One-Click Deploy

1. Go to [railway.app](https://railway.app)
2. Click "New Project"
3. Select "Deploy from GitHub repo"
4. Connect your GitHub and select this repository
5. Railway will auto-detect and deploy!

### Option 2: Railway CLI

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login to Railway
railway login

# Initialize project
railway init

# Deploy
railway up
```

---

## Enable Email Notifications (Optional)

To send actual emails when orders are placed:

### Step 1: Create EmailJS Account
1. Go to [emailjs.com](https://www.emailjs.com/)
2. Sign up for free (200 emails/month)

### Step 2: Add Email Service
1. Go to "Email Services" → "Add New Service"
2. Choose Gmail, Outlook, or your email provider
3. Connect your email account
4. Note your **Service ID**

### Step 3: Create Email Template
1. Go to "Email Templates" → "Create New Template"
2. Use this template:

**Subject:**
```
New Warehouse Sale Order - {{order_id}}
```

**Body:**
```
NEW ORDER RECEIVED

Order ID: {{order_id}}
Shop Name: {{shop_name}}
Customer Email: {{customer_email}}
Branch: {{branch}}

ORDER ITEMS:
{{order_items}}

TOTAL: ${{order_total}}

---
This order should be fulfilled by: {{branch_email}}
```

3. Note your **Template ID**

### Step 4: Get Public Key
1. Go to "Account" → "API Keys"
2. Copy your **Public Key**

### Step 5: Update the Code
Edit `public/index.html` and find the `EMAILJS_CONFIG` section near the top:

```javascript
const EMAILJS_CONFIG = {
  enabled: true,  // Change to true
  publicKey: 'YOUR_PUBLIC_KEY',      // Paste your public key
  serviceId: 'YOUR_SERVICE_ID',      // Paste your service ID
  templateId: 'YOUR_TEMPLATE_ID'     // Paste your template ID
};
```

### Step 6: Redeploy
```bash
railway up
```

---

## Local Development

```bash
# Install dependencies
npm install

# Start server
npm start

# Open in browser
open http://localhost:3000
```

---

## Configuration

### Change Password
Edit `public/index.html` and find:
```javascript
const CORRECT_PASSWORD = "buyfromchc";
```

### Change Branch Emails
Edit `public/index.html` and find:
```javascript
const BRANCH_EMAILS = {
  "Woodbridge": "woodbridge@chcpaint.com",
  "Markham": "markham@chcpaint.com",
  "Ottawa": "ottawa@chcpaint.com",
  "Hamilton": "hamilton@chcpaint.com",
  "Oakville": "oakville@chcpaint.com",
  "St. Catharines": "stcatharines@chcpaint.com"
};
```

---

## Tech Stack

- **Frontend:** HTML, Tailwind CSS, Vanilla JavaScript
- **Backend:** Node.js, Express
- **Email:** EmailJS (optional)
- **Hosting:** Railway

---

## Support

Contact daniel@chcpaint.com for support.
