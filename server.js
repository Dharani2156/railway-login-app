const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ✅ MySQL setup — replace with Railway credentials when deploying
const pool = mysql.createPool({
    host: process.env.MYSQLHOST,
    user: process.env.MYSQLUSER,
    password: process.env.MYSQLPASSWORD,
    database: process.env.MYSQLDATABASE,
    port: process.env.MYSQLPORT,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
}).promise();

// Signup route
app.post('/signup', async (req, res) => {
    const { username, password, email } = req.body;

    if (!username || !password || !email || password.length < 3 || username.length < 3) {
        return res.status(400).json({ message: 'All fields are required. Username and password must be at least 3 characters.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        await pool.query(
            'INSERT INTO USER (username, password, email) VALUES (?, ?, ?)',
            [username, hashedPassword, email]
        );

        res.status(201).json({ message: 'User created successfully! Please login.' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'Username or email already exists.' });
        }
        console.error('Signup Error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    try {
        const [rows] = await pool.query('SELECT * FROM USER WHERE username = ?', [username]);

        if (rows.length === 0) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (isMatch) {
            res.status(200).json({ message: 'Login successful!' });
        } else {
            res.status(401).json({ message: 'Invalid username or password' });
        }
    } catch (error) {
        console.error('Login Error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`);
});

