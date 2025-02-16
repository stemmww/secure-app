
# Secure App Project

A secure web application built with Node.js, Express, MongoDB, and EJS. This project includes user authentication, two-factor authentication (2FA), QR code generation, and email notifications.

## 📂 Project Structure

```
secure-app with LAB WORK/
├── .env                    # Environment variables
├── package.json           # Project metadata and dependencies
├── server.js              # Main server file (Express.js)
├── public/                # Static files (CSS, JS, images)
├── views/                 # EJS templates for rendering views
├── routes/                # Express route handlers
└── models/                # Mongoose models (e.g., User)
```

## 🚀 Installation

1. **Clone the repository:**  
   ```bash
   git clone https://github.com/yourusername/secure-app.git
   cd secure-app
   ```

2. **Install dependencies:**  
   ```bash
   npm install
   ```

3. **Set up environment variables:**  
   Create a `.env` file with the following content:
   ```env
   PORT=3000
   MONGO_URI=your_mongodb_connection_string
   SESSION_SECRET=your_secret_key
   EMAIL_USER=your_email@example.com
   EMAIL_PASS=your_email_password
   ```

4. **Start the server:**  
   ```bash
   npm start
   ```

   The server will run at: `http://localhost:3000`

## Scripts
- `npm start` - Starts the server  
- `npm test` - Runs tests (if implemented)  

## Dependencies
- `bcryptjs` - Password hashing  
- `crypto` - Encryption and security functions  
- `dotenv` - Environment variable management  
- `ejs` - Template engine for rendering pages  
- `express` - Web framework for Node.js  
- `express-session` - Session management  
- `express-validator` - Input validation  
- `mongodb` & `mongoose` - Database and ODM  
- `multer` - File uploads  
- `nodemailer` - Email service  
- `qrcode` - QR code generation  
- `speakeasy` - Two-factor authentication (TOTP)  

## Features
- User registration and login with hashed passwords  
- Two-Factor Authentication (2FA) using QR codes and TOTP  
- Secure sessions and input validation  
- MongoDB database integration with Mongoose  
- Real-time QR code generation  
- Email verification via Nodemailer  

## Security Considerations
- Use a strong `SESSION_SECRET` value in `.env`.  
- Enable `HTTPS` and set `secure: true` for cookies in production.  
- Validate and sanitize user inputs using `express-validator`.  

## Contributing
Contributions are welcome! Please fork this repository and submit a pull request.

## License
This project is licensed under the MIT License.
