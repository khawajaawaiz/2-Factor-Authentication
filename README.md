# 🔐 2-Factor Authentication System (PostgreSQL + Node.js)

A robust and secure Full-Stack Authentication system featuring **Two-Factor Authentication (2FA)**, built with Node.js and migrated to PostgreSQL for high-performance relational data management.

![Project Screenshot](https://raw.githubusercontent.com/khawajaawaiz/2-Factor-Authentication/main/public/images/preview.png) _(Note: Add your own screenshot link here)_

## 🚀 Features

- **JWT-Based Authentication**: Secure session management using Access and Refresh tokens.
- **Two-Factor Authentication (2FA)**: QR Code-based setup compatible with Google Authenticator and Authy.
- **Secure Data Storage**: Manual PostgreSQL schema design with Sequelize ORM.
- **Token Blacklisting**: Custom logout logic to invalidate tokens instantly.
- **Security First**: Password hashing with Bcrypt and AES-256-CBC encryption for sensitive TOTP secrets.
- **Premium UI**: Sleek, responsive dark-mode interface with smooth micro-interactions.
- **Periodic Cleanup**: Automated background process to clean up expired blacklisted tokens.

## 🛠️ Tech Stack

- **Backend**: Node.js, Express.js
- **Database**: PostgreSQL with Sequelize ORM
- **Security**: Passport.js, JWT, Speakeasy (TOTP), Bcrypt, Crypto (AES-256)
- **Frontend**: Vanilla JavaScript, HTML5, CSS3 (Modern Glassmorphism Design)

## 📋 Prerequisites

Before running this project, ensure you have:

- [Node.js](https://nodejs.org/) installed
- [PostgreSQL](https://www.postgresql.org/) installed and running
- [PgAdmin4](https://www.pgadmin.org/) (optional, for DB management)

## ⚙️ Setup & Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/khawajaawaiz/2-Factor-Authentication.git
   cd 2-Factor-Authentication
   ```

2. **Install dependencies:**

   ```bash
   npm install
   ```

3. **Environment Setup:**
   Create a `.env` file in the root directory and copy the values from `.env.example`:

   ```env
   # Example .env configuration
   DB_NAME=2FA
   DB_USER=postgres
   DB_PASSWORD=your_password
   DB_HOST=localhost
   DB_PORT=5432
   JWT_SECRET=your_secret_key
   ENCRYPTION_KEY=d7b8f9e2a1c4b3d5e6f7a8b9c0d1e2f3
   ENCRYPTION_IV=a1b2c3d4e5f6g7h8
   ```

4. **Database Setup:**
   Execute the manual SQL commands provided in PgAdmin4 to create the `Users` and `Blacklists` tables.

5. **Run the Application:**
   ```bash
   npm run dev
   ```
   The server will start on `http://localhost:7001`.

## 🛡️ Security Flow

1. **User Login**: Standard username/password check via Passport.js.
2. **MFA Check**: If 2FA is active, an initial token is issued, but full access is restricted.
3. **TOTP Verification**: User enters the 6-digit code from their authenticator app.
4. **Final Session**: A secure, elevated JWT is issued upon successful verification.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the issues page.

## 📝 License

This project is [MIT](https://opensource.org/licenses/MIT) licensed.
