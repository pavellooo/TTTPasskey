# HTTPS Setup & Let's Encrypt Migration Guide

## Current Setup: Self-Signed Certificate (Local Development)

Your backend is now running HTTPS with a self-signed certificate at:
- **Certificate**: `Backend/certs/server.crt`
- **Private Key**: `Backend/certs/server.key`

These certificates are valid for 365 days (until January 26, 2027).

### Starting the HTTPS Server

```bash
cd Backend
npm install
npm start
```

The backend will start on `https://localhost:5200`.

**Note**: Browsers will show a security warning for self-signed certificates. You can safely accept/bypass this in development.

---

## Switching to Let's Encrypt (Production)

When you have a domain and host your app online, follow these steps:

### Step 1: Obtain Let's Encrypt Certificates

Use **Certbot** (the official Let's Encrypt client):

**On Windows:**
```powershell
# Install certbot via Python
pip install certbot certbot-dns-cloudflare

# Or use: choco install certbot
choco install certbot
```

**On Linux/macOS:**
```bash
sudo apt-get install certbot  # Debian/Ubuntu
brew install certbot         # macOS
```

### Step 2: Generate Certificates

```bash
# For standalone (requires port 80 open)
certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com

# Or with DNS validation
certbot certonly --dns-cloudflare -d yourdomain.com -d www.yourdomain.com
```

Certificates are typically generated at:
- **Linux/macOS**: `/etc/letsencrypt/live/yourdomain.com/`
- **Windows**: `C:\Certbot\live\yourdomain.com\`

### Step 3: Update Environment Variables

Set environment variables to point to your Let's Encrypt certificates:

```bash
# .env file
SSL_CERT_PATH=/etc/letsencrypt/live/yourdomain.com/fullchain.pem
SSL_KEY_PATH=/etc/letsencrypt/live/yourdomain.com/privkey.pem
```

Or on Windows PowerShell:
```powershell
$env:SSL_CERT_PATH = "C:\Certbot\live\yourdomain.com\fullchain.pem"
$env:SSL_KEY_PATH = "C:\Certbot\live\yourdomain.com\privkey.pem"
```

### Step 4: Update Frontend URLs

Replace `https://localhost:5200` with `https://yourdomain.com` in:
- `Frontend/src/App.js`
- `Frontend/src/component/passkey.js`
- `Backend/Server.js` (expectedOrigin values)

### Step 5: Update Backend Origin Check

In `Backend/Server.js`, update the `expectedOrigin` values:

```javascript
// Change from:
expectedOrigin: 'https://localhost:5200'

// To:
expectedOrigin: 'https://yourdomain.com'
```

### Step 6: Auto-Renewal (Recommended)

Let's Encrypt certificates expire every 90 days. Set up automatic renewal:

**Linux/macOS:**
```bash
# Create cron job
sudo crontab -e

# Add this line (runs renewal daily at 2 AM)
0 2 * * * certbot renew --quiet
```

**Windows:**
Use Task Scheduler to run:
```
certbot renew --quiet
```
daily or weekly.

---

## Code Structure for Easy Migration

The backend uses environment variables for certificate paths:

```javascript
// Backend/Server.js (lines ~1-30)
const sslCertPath = process.env.SSL_CERT_PATH || path.join(__dirname, 'certs', 'server.crt');
const sslKeyPath = process.env.SSL_KEY_PATH || path.join(__dirname, 'certs', 'server.key');

// Defaults to self-signed certs if env vars not set
// Automatically uses Let's Encrypt certs when env vars are configured
```

This means **no code changes are needed** when switching to Let's Encrypt—just set the environment variables!

---

## Troubleshooting

### "SELF_SIGNED_CERT_IN_CHAIN" Error
- Normal for development with self-signed certs
- Use `NODE_TLS_REJECT_UNAUTHORIZED=0` for testing (not recommended for production)

### Certificate Mismatch Error
- Ensure `expectedOrigin` in `Server.js` matches your actual domain
- For localhost: should be `https://localhost:5200`
- For production: should be `https://yourdomain.com`

### Port Already in Use
```bash
# Kill process on port 5200
lsof -ti:5200 | xargs kill -9  # macOS/Linux
Get-Process -Id (Get-NetTCPConnection -LocalPort 5200).OwningProcess | Stop-Process  # Windows
```

---

# 🚀 Complete Production Deployment Checklist

When deploying online, follow this comprehensive checklist:

## Phase 1: Pre-Deployment Setup

### 1.1 Secure Your JWT Keys ⚠️ CRITICAL
- ✅ **Your JWT keys in `.env` are already generated and secure**
- ✅ **NEVER commit `.env` to git** - Add to `.gitignore`
- ✅ Store on hosting server securely using provider's secret management:
  - **Heroku**: Config Vars dashboard
  - **AWS**: Systems Manager Parameter Store / Secrets Manager
  - **DigitalOcean**: App Platform > Environment
  - **Self-hosted**: File permissions `chmod 600 .env`

**Current configuration (ALREADY DONE):**
```
JWT_PRIVATE_KEY=<your_key>           # Keep secret! Signing key
JWT_PUBLIC_KEY=<your_key>            # Can be public, verification key
JWT_ACCESS_TOKEN_EXPIRY=15m          # Short-lived access
JWT_REFRESH_TOKEN_EXPIRY=1d          # Long-lived refresh
```

### 1.2 Database Credentials
Update `.env` with **production database credentials**:
```
DB_HOST=your-db-server-ip
DB_USER=prod_user
DB_PASSWORD=<STRONG_PASSWORD>        # Generate random, 20+ chars
DB_NAME=webauthn_passkey
```

### 1.3 Update Frontend API URLs
Replace `https://localhost:5200` with your production domain in:
- [Frontend/src/App.js](../Frontend/src/App.js)
- [Frontend/src/component/passkey.js](../Frontend/src/component/passkey.js)

**Option A: Hardcode**
```javascript
// Replace: 'https://localhost:5200/...'
// With: 'https://yourdomain.com/...'
```

**Option B: Environment variables (recommended)**
Create `Frontend/.env.production`:
```
REACT_APP_API_URL=https://yourdomain.com
```
Then use in code:
```javascript
const API_URL = process.env.REACT_APP_API_URL || 'https://localhost:5200';
// axios.post(`${API_URL}/webauthn/register`, ...)
```

### 1.4 Update Backend Origin Checks
In [Backend/Server.js](../Backend/Server.js), update BOTH `expectedOrigin` values:
- Line ~174 (registration verification)
- Line ~377 (authentication verification)

```javascript
// Change from:
expectedOrigin: 'https://localhost:5200'

// To:
expectedOrigin: 'https://yourdomain.com'
```

---

## Phase 2: Choose Hosting & SSL Setup

### 2.1 Hosting Options

| Provider | Difficulty | SSL | Env Vars | Auto-Deploy | Cost |
|----------|-----------|-----|----------|------------|------|
| **Heroku** | Very Easy | Auto ✅ | Built-in ✅ | Git push | $7-50/mo |
| **Railway** | Easy | Auto ✅ | Built-in ✅ | Git push | $5-50/mo |
| **Render** | Easy | Auto ✅ | Built-in ✅ | Git push | $7-50/mo |
| **DigitalOcean** | Medium | Manual/Auto | Built-in ✅ | GitHub | $5-20/mo |
| **AWS EC2** | Hard | Manual | Parameter Store | Manual | $5-30/mo |
| **Self-hosted VPS** | Hard | Manual (Certbot) | Manual | Manual | $2-10/mo |

**Recommendation**: Start with **Heroku, Railway, or Render** - they handle SSL/TLS automatically.

### 2.2 SSL/TLS Automatic Setup (Easiest)
Hosting providers like Heroku/Railway auto-provide Let's Encrypt certificates when you:
1. Register a domain
2. Point domain to their servers (DNS CNAME)
3. Certificates auto-renew every 90 days
4. **No setup needed!**

### 2.3 SSL/TLS Manual Setup (Self-hosted/VPS)

**Install Certbot:**
```bash
sudo apt-get update
sudo apt-get install certbot python3-certbot-nginx
```

**Generate certificate:**
```bash
# Option 1: Standalone (simple, ~5 min downtime)
sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com

# Option 2: DNS challenge (no downtime)
sudo certbot certonly --dns-cloudflare -d yourdomain.com
```

**Configure `.env` on server:**
```
SSL_CERT_PATH=/etc/letsencrypt/live/yourdomain.com/fullchain.pem
SSL_KEY_PATH=/etc/letsencrypt/live/yourdomain.com/privkey.pem
```

**Enable auto-renewal:**
```bash
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer

# Verify renewal works
sudo certbot renew --dry-run
```

---

## Phase 3: Build & Deploy

### 3.1 Prepare Frontend Build
```bash
cd Frontend
npm run build
# Creates: Frontend/build/ folder with optimized static files
```

### 3.2 Prepare Backend for Production

**Option A: Deploy as-is (Backend serves frontend)**
```bash
# Copy built frontend to backend
cp -r Frontend/build Backend/build

# Install dependencies
cd Backend
npm install --production

# Ensure .env is on server with all secrets!
```

**Option B: Use separate servers**
- Frontend: Deploy to Netlify/Vercel (separate process)
- Backend: Deploy to your Node.js host
- Update CORS in `Backend/Server.js`:
```javascript
app.use(cors({
  origin: 'https://yourdomain.com',  // Frontend URL
  credentials: true
}));
```

### 3.3 Set Environment Variables on Hosting

**Heroku example:**
```bash
heroku config:set JWT_PRIVATE_KEY="<paste_key>"
heroku config:set JWT_PUBLIC_KEY="<paste_key>"
heroku config:set DB_HOST="your-db-host"
heroku config:set DB_PASSWORD="strong_password"
# ... etc for all vars in .env
```

**DigitalOcean/Railway/Render**: Use their web dashboard to paste `.env` contents

### 3.4 Start Production Server

**Using PM2 (recommended):**
```bash
npm install -g pm2
pm2 start Backend/Server.js --name "passkey"
pm2 save
pm2 startup
```

**Or direct:**
```bash
NODE_ENV=production npm start
```

---

## Phase 4: Verify Production Setup

### 4.1 Test HTTPS Connection
```bash
curl -I https://yourdomain.com
# Should show: HTTP/2 200
```

### 4.2 Test SSL Certificate
Visit: https://www.ssllabs.com/ssltest/analyze.html?d=yourdomain.com
- Should show **A or A+** rating

### 4.3 Test API Endpoints
```bash
curl -X POST https://yourdomain.com/webauthn/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}'
```

### 4.4 Verify Cookies in Browser
1. Visit https://yourdomain.com
2. Open DevTools (F12) → Application → Cookies
3. Should see: `accessToken`, `refreshToken` with:
   - ✅ HttpOnly
   - ✅ Secure
   - ✅ SameSite: Strict

### 4.5 Check Certificate Renewal
```bash
# For manual/self-hosted:
sudo certbot certificates
# Should show expiration date ~90 days away
```

---

## Phase 5: Security Checklist ✅

Before going live:

- [ ] `.env` file NOT in git (.gitignore present)
- [ ] JWT private key is strong and unique
- [ ] Database password is 20+ random characters
- [ ] SSL/TLS certificate is valid (not self-signed)
- [ ] All API URLs point to production domain
- [ ] expectedOrigin values updated to domain
- [ ] HTTPS enforced (HTTP redirects to HTTPS)
- [ ] CORS origin set to your domain (not `*`)
- [ ] Cookies have HttpOnly + Secure + SameSite flags
- [ ] Certificate auto-renewal configured
- [ ] Backups enabled for database
- [ ] Monitoring/alerts set up

---

## Phase 6: Ongoing Maintenance

### Certificate Renewal (Automatic)
Let's Encrypt certs expire every 90 days. Your setup auto-renews, but monitor:
```bash
certbot certificates  # Check expiration
```

### Database Backups
```bash
# Regular MySQL backups (add to cron job)
mysqldump -u root -p webauthn_passkey > backup_$(date +%Y%m%d_%H%M%S).sql
```

### Monitoring
Set up alerts for:
- Certificate expiration (30 days warning)
- Server uptime
- Database errors
- Failed authentications

---

## Summary: Local → Production Changes

| Item | Local | Production |
|------|-------|------------|
| Frontend URL | `https://localhost:5200` | `https://yourdomain.com` |
| Backend Origin | `https://localhost:5200` | `https://yourdomain.com` |
| SSL Certificate | Self-signed (Backend/certs/) | Let's Encrypt (auto) |
| JWT Keys | In local `.env` | In server `.env` / secrets manager |
| Database | Local MySQL | Production MySQL server |
| Port | 5200 public | Behind reverse proxy (80/443) |

**Code changes needed:** Frontend URLs + Backend origin check
**Code changes NOT needed:** JWT logic, cookie security, authentication flow
