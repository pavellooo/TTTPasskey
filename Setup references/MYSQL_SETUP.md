# MySQL Configuration Guide

## Prerequisites
- MySQL Server installed and running
- MySQL credentials: 
  - User: `root`
  - Password: `Hashtag@123`

## Step 1: Connect to MySQL

### Option A: Using Command Line
```bash
mysql -u root -p
# Enter password: Hashtag@123
```

## Step 2: Create Database and Tables

Run the following SQL commands:

```sql
-- Create the database
CREATE DATABASE IF NOT EXISTS webauthn_passkey;
USE webauthn_passkey;

-- Create the users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    user_id VARCHAR(255) NOT NULL,
    challenge VARCHAR(255),
    credential LONGTEXT,
    public_key LONGTEXT,
    credential_id LONGTEXT,
    counter INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Step 3: Verify Setup

Confirm the database and table were created:

```sql
USE webauthn_passkey;
SHOW TABLES;
DESCRIBE users;
```

You should see the `users` table with all the required columns.

## Step 4: Start the Node Server

Once the database is configured:

```bash
cd Backend
npm install
npm run start
```

The server should output:
```
Server running on port 5200...
Connected to Database
```

## Connection Details in Server.js

The Node.js application connects to MySQL with these settings:
- **Host:** localhost
- **User:** root
- **Password:** Hashtag@123
- **Database:** webauthn_passkey

If you need to change credentials, update the connection settings in `Server.js` (lines 18-20).

## Troubleshooting

### "Cannot find module 'mysql'"
- Run `npm install` in the Backend folder
- Ensure `mysql2` is installed (check package.json)

### "Connection refused"
- Verify MySQL Server is running
- Check that credentials are correct
- Confirm the database exists with `SHOW DATABASES;`

### "Access denied for user 'root'"
- Verify the password is `Hashtag@123`
- Make sure you're using the correct username

### "Unknown database"
- Ensure the database `webauthn_passkey` was created
- Run the database creation SQL commands above
