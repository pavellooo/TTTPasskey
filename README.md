# Project Passkey - Tic Tac Toe

A web application exploring the WebAuthn passkey authentication flow integrated with a Tic Tac Toe game. This project demonstrates secure, passwordless authentication using the FIDO2 standard.

It is currently deployed using Heroku at the following URL:
https://passkey-tictactoe-spa-f5b6f75d5241.herokuapp.com

## Project Overview

This is a full-stack application with:
- **Frontend**: React-based single-page application (SPA)
- **Backend**: Node.js/Express server with WebAuthn authentication
- **Database**: MySQL for user credentials and sessions
- **Passkey Authentication**: Secure FIDO2 WebAuthn implementation

## Prerequisites

- Node.js 20.x
- npm 10.x
- MySQL server (for database)
- Heroku CLI (for deployment)

## Project Structure

```
├── Frontend/          # React application
├── Backend/           # Express server
├── build-and-deploy.js # Build automation script
├── Procfile           # Heroku deployment configuration
└── package.json       # Root package configuration
```

## Getting Started

### Local Development

1. **Install root dependencies**:
   ```bash
   npm ci
   ```

2. **Install Frontend dependencies** (in your IDE or terminal):
   ```bash
   cd Frontend
   npm ci
   npm start
   ```

3. **Install and run Backend** (in another terminal):
   ```bash
   cd Backend
   npm ci
   npm start
   ```

The frontend will be available at `http://localhost:3000` and the backend API will be running on the port configured in `Backend/Server.js`.

## Build and Deployment

### Building for Production

To build the frontend and prepare for deployment:

```bash
npm run deploy
```

This command:
1. Installs and builds the React frontend
2. Copies the built frontend files to the backend `build/` directory
3. The backend serves the frontend static files

Alternatively, you can use the build-and-deploy.js script directly:
```bash
node build-and-deploy.js
```

### Heroku Deployment

This project is configured for easy deployment to Heroku using the provided `Procfile`.

#### Deploy Steps:

1. **Set up Heroku (first time only)**:
   ```bash
   heroku login
   heroku create your-app-name
   ```

2. **Configure environment variables** (if needed):
   ```bash
   heroku config:set VARIABLE_NAME=value
   ```

3. **Deploy to Heroku**:
   ```bash
   git push heroku main
   ```

Heroku will automatically:
- Detect Node.js project
- Run `npm run heroku-postbuild` to build frontend and install backend dependencies
- Start the app using the command in `Procfile` (node Backend/Server.js)
- Serve your application at your Heroku domain

#### Available NPM Scripts:

- `npm start` - Start the backend server
- `npm run build` - Build frontend and install dependencies
- `npm run heroku-postbuild` - Heroku build hook (auto-executed during deployment)
- `npm run deploy` - Local build and deployment preparation
- `npm run start-backend` - Explicitly start the backend

### Environment Variables

Configure the following environment variables for your Heroku app. These are used by the backend server for database connections, authentication, and other configurations.

#### Setting Environment Variables on Heroku:

```bash
# Set individual variables
heroku config:set DATABASE_URL="mysql://user:password@host:port/database"
heroku config:set JWT_PUBLIC_KEY="your-public-key"
heroku config:set NODE_ENV="production"

# Or set multiple at once
heroku config:set VAR1=value1 VAR2=value2 VAR3=value3
```
The heroku variables should follow the same names as in the [.env.example] file

#### View Current Configuration:

```bash
heroku config
```

#### Common Environment Variables:

These variables should be set in your `.env` file locally and in Heroku config:
- `DATABASE_URL` - MySQL connection string
- `JWT_SECRET` - Secret key for JWT token signing
- `NODE_ENV` - Set to "production" for Heroku
- `PORT` - Server port (Heroku automatically sets this)

### SSL Certificates

If using HTTPS with SSL certificates locally or on Heroku:

#### Local Development:

1. Generate self-signed certificates (for development only):
   ```bash
   openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
   ```

2. Store certificates in a `certs/` directory (excluded from git):
   ```bash
   mkdir certs
   # Move your cert.pem and key.pem files here
   ```

3. Add `certs/` to `.gitignore`:
   ```
   certs/
   ```

Note that certs have been left in the backend for testing purposes. They are not used in the current Heroku deployment. It is highly recommended that they should be rotated often and never be uploaded to the repository.

#### Heroku Deployment:

For production SSL on Heroku:
- Use Heroku's **Automatic Certificate Management** (ACM) - automatically provides free SSL certificates
- Or configure a custom domain with your own SSL certificate through Heroku's settings
- No need to commit certificate files to the repository

- Heroku has many database management addons to choose from with different pricing tiers. Choose one that is compatible with MySQL. JawsDB free tier provides 5 megabytes of storage and a very simple setup guide, so that is what we chose to use.

#### .gitignore:

Create or update `.gitignore` to exclude sensitive files and generated builds:

```
# Dependencies
node_modules/

# Generated builds
Frontend/build/
Backend/build/

# Environment variables
.env
.env.local

# SSL Certificates
certs/

# IDE
.DS_Store
.vscode/
.idea/
```

## Database Setup

Refer to [Setup references/MYSQL_SETUP.md](Setup%20references/MYSQL_SETUP.md) for MySQL database configuration and schema setup.

## Technology Stack

- **Frontend**: React, CSS
- **Backend**: Express.js, Node.js
- **Authentication**: @simplewebauthn/server (FIDO2/WebAuthn)
- **Database**: MySQL
- **Security**: JWT, CORS, Rate Limiting, Cookie Parser

## License

ISC
