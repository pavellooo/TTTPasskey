# Project Passkey - Tic Tac Toe

This project implements a "passkey authentication" flow integrated with a Tic Tac Toe web application. Users can play against the system while testing secure, passwordless FIDO2 WebAuthn authentication.

**Live Demo**: https://passkey-tictactoe-spa-f5b6f75d5241.herokuapp.com  
**Short URL**: https://tinyurl.com/TTTSPA

## Project Overview

This is a full-stack application with:
- **Frontend**: React-based single-page application (SPA)
- **Backend**: Node.js/Express server with WebAuthn passkey authentication
- **Database**: MySQL for user credentials and passkey data
- **Authentication**: Secure FIDO2 WebAuthn implementation (passwordless login)
- **Deployment**: Configured for Heroku with Procfile

## Prerequisites

Before you begin, ensure you have installed:
- **Node.js** 20.x or higher ([download](https://nodejs.org/))
- **npm** 10.x or higher (comes with Node.js)
- **MySQL Server** 8.0+ ([download](https://www.mysql.com/downloads/))
  - Recommended: [MySQL Community Server](https://dev.mysql.com/downloads/mysql/) or [XAMPP](https://www.apachefriends.org/) (includes MySQL)
- **Git** (for version control)
- **Heroku CLI** (optional, only if deploying to Heroku)

## Project Structure

```
├── Frontend/              # React application (SPA)
├── Backend/               # Express.js server with WebAuthn
│   ├── Server.js          # Main server file
│   ├── package.json       # Backend dependencies
│   ├── .env.example       # Environment variables template
│   └── certs/             # SSL certificates (for local HTTPS)
├── Setup references/      # Database setup scripts
├── build-and-deploy.js    # Build automation script
├── Procfile              # Heroku deployment config
└── package.json          # Root package config
```

## Getting Started

### Step 1: Clone and Install Dependencies

```bash
# Clone the repository (if you haven't already)
git clone <your-repo-url>
cd TTTPasskey

# Install root-level dependencies
npm ci
```

### Step 2: Configure Environment Variables

1. **Navigate to the Backend folder**:
   ```bash
   cd Backend
   ```

2. **Create `.env` file from the template**:
   
   Note that there may already be a `.env` file in the Backend folder for testing purposes. If you want to use that, you can skip this step. However, it is recommended that you create your own `.env` file with your own credentials and JWT keys.

   **On Windows (PowerShell)**:
   ```powershell
   Copy-Item .env.example .env
   ```
   
   **On macOS/Linux**:
   ```bash
   cp .env.example .env
   ```

3. **Edit the `.env` file** with your configuration. At minimum, you need to set:
   - `DB_PASSWORD`: Your MySQL root password
   - JWT keys (see below)

   See [Environment Variables Reference](#environment-variables) for full details.

### Step 3: Generate JWT Keys

The application uses RSA JWT tokens for authentication. You need to generate a private and public key pair:

1. **On Windows (PowerShell)** - Install OpenSSL first:
   ```powershell
   # If you have Git Bash installed, you can use it:
   # "C:\Program Files\Git\bin\bash.exe" -c "openssl genrsa -out private.pem 2048 && openssl rsa -in private.pem -pubout -out public.pem"
   
   # Or use WSL:
   wsl openssl genrsa -out private.pem 2048
   wsl openssl rsa -in private.pem -pubout -out public.pem
   ```

2. **On macOS/Linux**:
   ```bash
   openssl genrsa -out private.pem 2048
   openssl rsa -in private.pem -pubout -out public.pem
   ```

3. **Add the keys to `.env`**:
   - Open `private.pem` and copy its contents
   - In `.env`, set `JWT_PRIVATE_KEY="<contents of private.pem>"`
   - Open `public.pem` and copy its contents
   - In `.env`, set `JWT_PUBLIC_KEY="<contents of public.pem>"`
   - Remember to preserve the `\n` characters in the newlines

   Example:
   ```
   JWT_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
   JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhk...\n-----END PUBLIC KEY-----"
   ```

### Step 4: Set Up MySQL Database

See [Setup references/MYSQL_SETUP.md](Setup%20references/MYSQL_SETUP.md) for detailed MySQL configuration, database creation, and troubleshooting.

### Step 5: Install Backend Dependencies

Still in the `Backend` folder:
```bash
npm ci
```

### Step 6: Run Local Development

You'll need **two terminal windows** for local development:

> **Note**: If `node_modules` directories don't exist locally, they'll be automatically reinstalled when you run the commands below.

**Terminal 1 - Start the Backend**:
```bash
cd Backend
npm install
npm start
```

You should see:
```
Server running on port 5200...
Connected to Database
```

**Terminal 2 - Start the Frontend** (from root directory):
```bash
cd Frontend
npm ci
npm start
```

You should see:
```
Compiled successfully!
You can now view frontend in the browser.

Local:            http://localhost:3000
```

**Access the application**: Open your browser to `http://localhost:3000`

> **Two Ways to Run the App:**
> 
> **Local Development** (right now):
> - You run two separate servers: Frontend on port 3000, Backend on port 5200
> - This lets you test changes instantly—modify a file and the frontend automatically reloads
> - Access the app at `http://localhost:3000`
> 
> **Deployment Mode** (after `npm run deploy`):
> - You run only the Backend on port 5200
> - The Backend contains the built frontend files (`Backend/build/`) and sends them to your browser
> - When you visit `http://localhost:5200`, the Backend simply gives you the pre-built frontend files
> - This mirrors how real web apps work in production—a single server delivers everything
> 
> **TL;DR**: Development = separate Frontend and Backend servers for fast iteration. Deployment = Backend has the built Frontend files and serves them like a real app would.

## Quick Reference

### Environment Variables

Key `.env` variables in `Backend/`:

| Variable | Default | Purpose |
|----------|---------|---------|
| `NODE_ENV` | `development` | Set to `production` for production |
| `PORT` | `5200` | Backend server port |
| `DB_HOST` | `localhost` | MySQL server host |
| `DB_USER` | `root` | MySQL username |
| `DB_PASSWORD` | `Hashtag@123` | MySQL password |
| `DB_NAME` | `webauthn_passkey` | Database name |
| `JWT_PRIVATE_KEY` | *(required)* | RSA private key (generate with OpenSSL) |
| `JWT_PUBLIC_KEY` | *(required)* | RSA public key |
| `RP_ID` | `localhost` | WebAuthn domain (for production: `your-app.herokuapp.com`) |
| `ORIGIN` | `http://localhost:5200` | CORS origin (for production: your Heroku URL) |

## Building for Production

### Build and Prepare for Deployment

To build the frontend and prepare everything for production:

```bash
npm run deploy
```

This command:
1. Installs frontend dependencies
2. Builds the React application for production
3. Copies the built files to `Backend/build/`
4. Backend will serve the frontend as static files

The output will look like:
```
🔨 Building frontend...
✅ Frontend built successfully
📋 Copying build files to backend...
✅ Deploy completed successfully!
```

Alternatively, run the build script directly:
```bash
node build-and-deploy.js
```

### Run the Local Build

Once the build is complete, you need to update one environment variable, then start the Backend:

**Update `Backend/.env`** (important!):
- Change `ORIGIN=http://localhost:3000` to `ORIGIN=http://localhost:5200`
- This tells the Backend that it's now serving the frontend, so CORS and WebAuthn work correctly

Then start the Backend:
```bash
cd Backend
npm start
```

Open your browser to `http://localhost:5200`. The Backend automatically serves the built frontend files from `Backend/build/`.

## Heroku Deployment

### Setup Steps

1. **Create Heroku App & Connect Git**:
   - Go to [Heroku Dashboard](https://dashboard.heroku.com)
   - Click "New" → "Create new app"
   - Enter your app name (e.g., `my-passkey-app`)
   - In the "Deploy" tab, connect your GitHub repo and enable automatic deploys

2. **Add JawsDB MySQL Add-on**:
   - In the Heroku Dashboard, go to "Resources" tab
   - Search for "JawsDB MySQL" in the Add-ons Marketplace
   - Select the "Kitefin Shared" plan (free tier)
   - Click "Attach to app"
   - This automatically sets `JAWSDB_URL` in your config variables
   - You may have to parse this URL to get `DB_HOST`, `DB_USER`, `DB_PASSWORD`, and `DB_NAME` for local testing
   - Also, you can use an app such as "HeidiSQL" or "MySQL Workbench" to connect to the JawsDB instance and run the SQL setup scripts from [Setup references/MYSQL_SETUP.md](Setup%20references/MYSQL_SETUP.md). You will have to parse the JAWSDB_URL to get the connection details for these apps.

3. **Configure Environment Variables**:
   - In the "Settings" tab, click "Reveal Config Vars"
   - Add the following variables:
     ```
     NODE_ENV=production
     JWT_PRIVATE_KEY=<your-private-key>
     JWT_PUBLIC_KEY=<your-public-key>
     RP_ID=your-app-name.herokuapp.com
     ORIGIN=https://your-app-name.herokuapp.com
     ```
   - Heroku automatically extracts DB credentials from `JAWSDB_URL`, so you don't need to set `DB_HOST`, `DB_USER`, `DB_PASSWORD` manually

4. **Initialize Database**:
   - Get your JawsDB connection string from the "Resources" tab (click JawsDB add-on)
   - Connect using MySQL client and run the SQL from [Setup references/MYSQL_SETUP.md](Setup%20references/MYSQL_SETUP.md)
   - Or use: `mysql -h <jawsdb-host> -u <user> -p<password> <database> < Setup\ references/database_setup.sql`

5. **Deploy**:
   - Push to your repo: `git push origin main`
   - Heroku automatically builds and deploys
   - Monitor logs: `heroku logs --tail`

Heroku automatically runs `npm run heroku-postbuild` to build the frontend and install dependencies.

### Alternative: Vercel

If Heroku removes free student benefits in the future, **Vercel** is a great alternative for hosting the frontend. Here's a quick start:

1. Push your code to GitHub
2. Go to [vercel.com](https://vercel.com) and sign in with GitHub
3. Click "Add New Project" → select your repo
4. Set `Root Directory` to `Frontend`
5. Add environment variables and deploy
6. For the Backend, consider **Railway** or **Render** (both have free tiers)

See Vercel's docs for more: https://vercel.com/docs

## Troubleshooting

| Issue | Solution |
|-------|----------|
| **Cannot find module 'dotenv'** | Ensure `.env` exists in `Backend/` folder. Copy `.env.example` to `.env` and restart the server. |
| **Connection refused** (Database) | Start MySQL Server. Windows: `net start MySQL80`. macOS: `brew services start mysql-community-server`. |
| **Unknown database** | Create the database using commands in [Setup references/MYSQL_SETUP.md](Setup%20references/MYSQL_SETUP.md). |
| **Invalid or expired token** | Regenerate JWT keys using OpenSSL (Step 3). Clear browser cookies and restart backend. |
| **Port already in use** (3000/5200) | Windows: `netstat -ano \| findstr :3000`. macOS: `lsof -ti:3000 \| xargs kill -9`. Then restart the server. |
| **CORS error** | Ensure `ORIGIN` in `.env` matches your frontend URL. Restart backend. |

## Development Tips

- **Hot reload**: Frontend dev server automatically reloads when you save changes
- **Backend changes**: Restart `npm start` to see changes
- **Database queries**: Use MySQL Workbench or command line to view/modify data
- **JWT debugging**: Decode tokens at [jwt.io](https://jwt.io) to inspect claims
- **API testing**: Use Postman or VS Code REST Client to test endpoints
- **Authentication**: @simplewebauthn/server (FIDO2/WebAuthn)
- **Database**: MySQL
- **Security**: JWT, CORS, Rate Limiting, Cookie Parser

## License

ISC
