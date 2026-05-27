const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const crypto = require('crypto');
const fs = require('fs');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const cookieParser = require('cookie-parser');
const { aesEncrypt, aesDecrypt, formatKey } = require('./aes');
const app = express();
const port = 3000;

// Setup multer for file uploads
const storage = multer.memoryStorage(); // Stores files in memory as Buffer
const upload = multer({ storage: storage });

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/downloads', express.static(path.join(__dirname, 'public', 'downloads')));

// JWT Secret Key
const JWT_SECRET = 'your_secret_key';

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/healthcrypt', { useNewUrlParser: true, useUnifiedTopology: true });

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', () => {
    console.log('Connected to MongoDB');
});

// Define User schema and model
const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    email: String,
    phone: String
});

const User = mongoose.model('User', userSchema);

// Serve HTML files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

// Middleware to Authenticate JWT
const authenticateToken = (req, res, next) => {
    const token = req.cookies?.token; // Ensure cookies are being parsed
    if (!token) {
        return res.status(401).send('Access Denied: No Token Provided');
    }
    try {
        const verified = jwt.verify(token, JWT_SECRET);
        req.user = verified; // Store user info in the request object
        next();
    } catch (error) {
        res.status(403).send('Invalid Token');
    }
};

// Serve the Dashboard (Protected Route)
app.get('/dashboard', authenticateToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});
app.use('/downloads', express.static(path.join(__dirname, 'public', 'downloads')));

// Encrypt Route
app.post('/encrypt', upload.single('file'), (req, res) => {
    const key = req.body.key;
    const file = req.file ? req.file.buffer : null;

    if (!key || !file) {
        return res.status(400).send('Key and file are required.');
    }

    try {
        // Generate a random IV (Initialization Vector)
        const iv = crypto.randomBytes(16);

        // Format key to 32 bytes for AES-256
        const keyBuffer = formatKey(key);

        const encrypted = aesEncrypt(keyBuffer, iv, file);

        const downloadDir = path.join(__dirname, 'public', 'downloads');
        if (!fs.existsSync(downloadDir)) {
            fs.mkdirSync(downloadDir);
        }

        const encryptedFileName = `${uuidv4()}.enc`;
        const encryptedFilePath = path.join(downloadDir, encryptedFileName);
        const ivFilePath = encryptedFilePath + '.iv';

        // Save the encrypted file and IV
        fs.writeFileSync(encryptedFilePath, encrypted);
        fs.writeFileSync(ivFilePath, iv);

        console.log('File encrypted successfully');
        res.send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Encryption Result</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        text-align: center;
                        background-color: #f9f9f9;
                        margin: 0;
                        padding: 0;
                    }
                    .container {
                        margin-top: 50px;
                    }
                    h1 {
                        color: #4CAF50;
                    }
                    p {
                        font-size: 18px;
                    }
                    a {
                        display: inline-block;
                        margin-top: 20px;
                        padding: 10px 20px;
                        text-decoration: none;
                        color: white;
                        background-color: #4CAF50;
                        border-radius: 5px;
                    }
                    a:hover {
                        background-color: #45a049;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Encryption Successful</h1>
                    <p>Your file has been encrypted and saved.</p>
                    <a href="/downloads/${encryptedFileName}" download>Download Encrypted File</a>
                </div>
            </body>
            </html>
        `);
    } catch (error) {
        console.error('Encryption error:', error);
        res.status(500).send('Error encrypting file');
    }
});

// Decrypt Route
app.post('/decrypt', upload.single('file'), (req, res) => {
    const key = req.body.key;
    const file = req.file ? req.file.buffer : null;

    if (!key || !file) {
        return res.status(400).send('Key and encrypted file are required.');
    }

    try {
        const ivFilePath = path.join(__dirname, 'public', 'downloads', req.file.originalname + '.iv');
        if (!fs.existsSync(ivFilePath)) {
            return res.status(400).send('Missing IV file for decryption.');
        }

        const iv = fs.readFileSync(ivFilePath);
        const keyBuffer = formatKey(key);
        const decrypted = aesDecrypt(keyBuffer, iv, file);

        const decryptedFileName = `${uuidv4()}.dec`;
        const decryptedFilePath = path.join(__dirname, 'public', 'downloads', decryptedFileName);

        // Save the decrypted file
        fs.writeFileSync(decryptedFilePath, decrypted);

        console.log('File decrypted successfully');
        res.send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Decryption Result</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        text-align: center;
                        background-color: #f9f9f9;
                        margin: 0;
                        padding: 0;
                    }
                    .container {
                        margin-top: 50px;
                    }
                    h1 {
                        color: #4CAF50;
                    }
                    p {
                        font-size: 18px;
                    }
                    a {
                        display: inline-block;
                        margin-top: 20px;
                        padding: 10px 20px;
                        text-decoration: none;
                        color: white;
                        background-color: #4CAF50;
                        border-radius: 5px;
                    }
                    a:hover {
                        background-color: #45a049;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Decryption Successful</h1>
                    <p>Your file has been decrypted and saved.</p>
                    <a href="/downloads/${decryptedFileName}" download>Download Decrypted File</a>
                </div>
            </body>
            </html>
        `);
    } catch (error) {
        console.error('Decryption error:', error);
        res.status(500).send('Error decrypting file');
    }
});

// Signup Route
app.post('/signup', async (req, res) => {
    const { username, password, email, phone } = req.body;
    if (!username || !password || !email || !phone) {
        return res.status(400).send('All fields are required.');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword, email, phone });
    try {
        await newUser.save();
        res.redirect('/');
    } catch (error) {
        console.error('Error saving user:', error);
        res.status(500).send('Error signing up');
    }
});

// Login Route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username: username });
        if (!user) {
            return res.status(401).send('Invalid username or password.');
        }
        const match = await bcrypt.compare(password, user.password);
        if (match) {
            const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h' });
            res.cookie('token', token, { httpOnly: true });
            res.redirect('/dashboard');
        } else {
            res.status(401).send('Invalid username or password.');
        }
    } catch (error) {
        console.error('Error finding user:', error);
        res.status(500).send('Error logging in');
    }
});

// Logout Route
app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/');
});

// Handle unmatched routes
app.use((req, res) => {
    res.status(404).send('Page Not Found');
});

// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
