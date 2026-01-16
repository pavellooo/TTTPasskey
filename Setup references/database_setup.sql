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
