const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const mysql = require('mysql2');

const app = express();

// CORS (lock this down to your frontend origin if you know it)
app.use(cors());

// Parse both JSON and URL-encoded bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// DB connection (consider mysql2/promise + pool for prod)
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Password!',
  database: 'myDiary'
});

connection.connect((err) => {
  if (err) {
    console.error('Error connecting to the database:', err);
    return;
  }
  console.log('Connected to the MySQL database!');
});

app.get('/', (req, res) => {
  res.status(200).json({ message: 'Successful' });
});

app.post('/registerUser', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).send('Email and password are required');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Parameterized query
    const sql = 'INSERT INTO Users (EmailID, HashedPassword) VALUES (?, ?)';
    connection.query(sql, [email, hashedPassword], (err) => {
      if (err) {
        console.error('registerUser error:', err);
        return res.status(500).send('Failed to register user');
      }
      return res.status(200).send('User registered');
    });
  } catch (err) {
    console.error('registerUser catch:', err);
    return res.status(500).send('Error while hashing password');
  }
});

app.post('/userLogin', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).send('Email and password are required');
    }

    const sql = 'SELECT ID, HashedPassword FROM Users WHERE EmailID = ? LIMIT 1';
    connection.query(sql, [email], async (err, results) => {
      if (err) {
        console.error('userLogin query error:', err);
        return res.status(500).send('DB error');
      }

      if (!results || results.length === 0) {
        return res.status(401).send('Invalid credentials');
      }

      const { ID: userID, HashedPassword } = results[0];
      const ok = await bcrypt.compare(password, HashedPassword);
      if (!ok) {
        return res.status(401).send('Invalid credentials');
      }

      return res.status(200).json({ userID });
    });
  } catch (err) {
    console.error('userLogin catch:', err);
    return res.status(500).send('Server error');
  }
});

app.post('/newPost', async (req, res) => {
  try {
    const { postTitle, postDescription, userID } = req.body || {};
    if (!userID || !postTitle || !postDescription) {
      return res.status(400).send('userID, postTitle and postDescription are required');
    }

    // Make sure your column names match exactly in DB:
    // Posts(UserID, postTitle, postDescription)
    const sql = 'INSERT INTO Posts (UserID, postTitle, postDescription) VALUES (?, ?, ?)';
    connection.query(sql, [userID, postTitle, postDescription], (err, result) => {
      if (err) {
        console.error('newPost error:', err);
        return res.status(500).send('Failed to create post');
      }
      return res.status(200).send('Post created');
    });
  } catch (err) {
    console.error('newPost catch:', err);
    return res.status(500).send('Server error');
  }
});

app.get('/getMyPosts', (req, res) => {
  const { userID } = req.query || {};

  if (!userID) {
    return res.status(400).send('userID is required');
  }

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
    if (!results || results.length === 0) {
      return res.status(404).send('Not found');
    }
    return res.status(200).json(results[0]);
  });
});
app.delete('/post/:id', (req, res) => {
  const { id } = req.params;
  const { userID } = req.query;

  if (!id || !userID) {
    return res.status(400).send('id and userID are required');
  }

  const sql = 'DELETE FROM Posts WHERE ID = ? AND UserID = ?';
  connection.query(sql, [id, userID], (err, result) => {
    if (err) {
      console.error('delete post error:', err);
      return res.status(500).send('Failed to delete post');
    }
    if (result.affectedRows === 0) {
      // Either post not found or doesn't belong to this user
      return res.status(404).send('Post not found');
    }
    return res.status(200).send('Deleted');
  });
});

app.listen(3000, () => {
  console.log('Server Started on port 3000!');
});
