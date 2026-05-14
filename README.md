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
| `EXPECTED_RP_ID` | `localhost` | WebAuthn domain (for production: `your-app.herokuapp.com`) |
| `EXPECTED_ORIGIN` | `https://localhost:5200` | CORS origin (for production: your Heroku URL) |

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

## Heroku Deployment

### Setup Steps

1. **Login to Heroku**:
   ```bash
   heroku login
   heroku create your-app-name
   ```

2. **Add MySQL database**:
   ```bash
   heroku addons:create cleardb:ignite
   heroku config | grep CLEARDB_DATABASE_URL
   ```

3. **Configure environment variables**:
   ```bash
   heroku config:set DB_HOST=your-db-host.cleardb.net
   heroku config:set DB_USER=your-db-user
   heroku config:set DB_PASSWORD=your-db-password
   heroku config:set DB_NAME=your-db-name
   heroku config:set JWT_PRIVATE_KEY="<your-private-key>"
   heroku config:set JWT_PUBLIC_KEY="<your-public-key>"
   heroku config:set EXPECTED_RP_ID=your-app-name.herokuapp.com
   heroku config:set EXPECTED_ORIGIN=https://your-app-name.herokuapp.com
   heroku config:set NODE_ENV=production
   ```

4. **Initialize database and deploy**:
   ```bash
   # Connect to MySQL and run database setup (same SQL as MYSQL_SETUP.md)
   mysql -h <your-host> -u <your-user> -p <your-db-name>
   
   # Deploy to Heroku
   git push heroku main
   heroku logs --tail
   ```

Heroku automatically runs `npm run heroku-postbuild` to build the frontend and install backend dependencies.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| **Cannot find module 'dotenv'** | Ensure `.env` exists in `Backend/` folder. Copy `.env.example` to `.env` and restart the server. |
| **Connection refused** (Database) | Start MySQL Server. Windows: `net start MySQL80`. macOS: `brew services start mysql-community-server`. |
| **Unknown database** | Create the database using commands in [Setup references/MYSQL_SETUP.md](Setup%20references/MYSQL_SETUP.md). |
| **Invalid or expired token** | Regenerate JWT keys using OpenSSL (Step 3). Clear browser cookies and restart backend. |
| **Port already in use** (3000/5200) | Windows: `netstat -ano \| findstr :3000`. macOS: `lsof -ti:3000 \| xargs kill -9`. Then restart the server. |
| **CORS error** | Ensure `EXPECTED_ORIGIN` in `.env` matches your frontend URL. Restart backend. |

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
