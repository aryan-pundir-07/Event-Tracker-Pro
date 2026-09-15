const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'event_tracker_secret_key_2026';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// SQLite Database Setup
const db = new sqlite3.Database('./event_tracker.db', (err) => {
    if (err) console.error("Database error:", err.message);
    else console.log("Connected to SQLite Database.");
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )`);

    // Updated Table Schema with date and status columns
    db.run(`CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        participants INTEGER DEFAULT 0,
        date TEXT,
        status TEXT DEFAULT 'Pending',
        owner TEXT NOT NULL
    )`);
});

// JWT Auth Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Access token required" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid or expired token" });
        req.user = user;
        next();
    });
};

// Authentication Routes
app.post('/api/signup', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Missing fields" });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], function(err) {
            if (err) return res.status(400).json({ error: "Username already taken" });
            res.status(201).json({ message: "User registered" });
        });
    } catch (err) {
        res.status(500).json({ error: "Server error" });
    }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: "Invalid credentials" });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: "Invalid credentials" });

        const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '2h' });
        res.json({ token, username: user.username });
    });
});

// Event Management Routes - Updated to insert date & status
app.post('/api/events', authenticateToken, (req, res) => {
    const { name, participants, date, status } = req.body;
    db.run(
        `INSERT INTO events (name, participants, date, status, owner) VALUES (?, ?, ?, ?, ?)`, 
        [name, participants || 0, date || null, status || 'Pending', req.user.username], 
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.status(201).json({ 
                id: this.lastID, 
                name, 
                participants, 
                date, 
                status: status || 'Pending', 
                owner: req.user.username 
            });
    });
});

app.get('/api/events', authenticateToken, (req, res) => {
    const { search, sortBy } = req.query;
    let query = `SELECT * FROM events`;
    let params = [];

    if (search) {
        query += ` WHERE name LIKE ?`;
        params.push(`%${search}%`);
    }

    if (sortBy === 'participants') {
        query += ` ORDER BY participants DESC`;
    } else {
        query += ` ORDER BY id DESC`;
    }

    db.all(query, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.delete('/api/events/:id', authenticateToken, (req, res) => {
    const eventId = req.params.id;
    db.get(`SELECT owner FROM events WHERE id = ?`, [eventId], (err, event) => {
        if (err || !event) return res.status(404).json({ error: "Event not found" });
        if (event.owner !== req.user.username) return res.status(403).json({ error: "Unauthorized operation" });

        db.run(`DELETE FROM events WHERE id = ?`, [eventId], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: "Event deleted" });
        });
    });
});
// Serve index.html for all frontend routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));