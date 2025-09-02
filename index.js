const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const mysql = require('mysql2');
require('dotenv').config();

const app = express();

/* ----------------------- CORS ----------------------- */
const ALLOWED_ORIGINS = [
  'http://127.0.0.1:5500',
  'http://localhost:5500',
  'http://localhost:3000',
  process.env.FRONTEND_ORIGIN || 'https://YOUR-VERCEL-APP.vercel.app',
];

app.use(
  cors({
    origin(origin, cb) {
      // allow same-origin (no Origin header) and the allowed list
      if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error(`Not allowed by CORS: ${origin}`));
    },
    methods: ['GET', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

/* -------------------- Parsers ----------------------- */
app.use(express.json()); // JSON is enough for your current routes

/* --------------------- MySQL ------------------------ */
const connection = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || 'Password!',
  database: process.env.DB_NAME || 'myDiary',
});

connection.connect((err) => {
  if (err) {
    console.error('DB connect error:', err);
    process.exit(1);
  }
  console.log('Connected to the MySQL database!');
});

/* --------------------- Routes ----------------------- */
// Health
app.get('/', (_req, res) => res.status(200).json({ message: 'OK' }));

// Register
app.post('/registerUser', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).send('Email and password are required');

    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = 'INSERT INTO Users (EmailID, HashedPassword) VALUES (?, ?)';
    connection.query(sql, [email, hashedPassword], (err) => {
      if (err) {
        console.error('registerUser error:', err);
        return res.status(500).send('Failed to register user');
      }
      return res.status(200).send('User registered');
    });
  } catch (e) {
    console.error('registerUser catch:', e);
    return res.status(500).send('Server error');
  }
});

// Login
app.post('/userLogin', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).send('Email and password are required');

    const sql = 'SELECT ID, HashedPassword FROM Users WHERE EmailID = ? LIMIT 1';
    connection.query(sql, [email], async (err, results) => {
      if (err) {
        console.error('userLogin query error:', err);
        return res.status(500).send('DB error');
      }
      if (!results || results.length === 0) return res.status(401).send('Invalid credentials');

      const { ID: userID, HashedPassword } = results[0];
      const ok = await bcrypt.compare(password, HashedPassword);
      if (!ok) return res.status(401).send('Invalid credentials');

      return res.status(200).json({ userID });
    });
  } catch (e) {
    console.error('userLogin catch:', e);
    return res.status(500).send('Server error');
  }
});

// Create post
app.post('/newPost', (req, res) => {
  const { postTitle, postDescription, userID } = req.body || {};
  if (!userID || !postTitle || !postDescription) {
    return res.status(400).send('userID, postTitle and postDescription are required');
  }

  const sql = 'INSERT INTO Posts (UserID, postTitle, postDescription) VALUES (?, ?, ?)';
  connection.query(sql, [userID, postTitle, postDescription], (err) => {
    if (err) {
      console.error('newPost error:', err);
      return res.status(500).send('Failed to create post');
    }
    return res.status(200).send('Post created');
  });
});

// Get posts for a user
app.get('/getMyPosts', (req, res) => {
  const { userID } = req.query || {};
  if (!userID) return res.status(400).send('userID is required');

  const sql = `
    SELECT ID, UserID, postTitle, postDescription
    FROM Posts
    WHERE UserID = ?
    ORDER BY ID DESC
  `;
  connection.query(sql, [userID], (err, results) => {
    if (err) {
      console.error('getMyPosts error:', err);
      return res.status(500).send('Failed to fetch posts');
    }
    return res.status(200).json(results);
  });
});

// Get a single post
app.get('/postById', (req, res) => {
  const { id } = req.query || {};
  if (!id) return res.status(400).send('id is required');

  const sql = `
    SELECT ID, UserID, postTitle, postDescription
    FROM Posts
    WHERE ID = ?
    LIMIT 1
  `;
  connection.query(sql, [id], (err, results) => {
    if (err) {
      console.error('postById error:', err);
      return res.status(500).send('Failed to fetch post');
    }
    if (!results || results.length === 0) return res.status(404).send('Not found');
    return res.status(200).json(results[0]);
  });
});

// Delete a post (only if belongs to the user)
app.delete('/post/:id', (req, res) => {
  const { id } = req.params;
  const { userID } = req.query;
  if (!id || !userID) return res.status(400).send('id and userID are required');

  const sql = 'DELETE FROM Posts WHERE ID = ? AND UserID = ?';
  connection.query(sql, [id, userID], (err, result) => {
    if (err) {
      console.error('delete post error:', err);
      return res.status(500).send('Failed to delete post');
    }
    if (result.affectedRows === 0) return res.status(404).send('Post not found');
    return res.status(200).send('Deleted');
  });
});

/* ------------------- Start -------------------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server Started on port ${PORT}!`);
});
