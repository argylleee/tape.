const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
const port = 5000;

app.use(express.json());
app.use(bodyParser.json());
app.use(cors());

const db  = mysql.createConnection({
    connectionLimit : 10,
    host            : process.env.DB_HOST,
    user            : process.env.DB_USER,
    password        : process.env.DB_PASSWORD,
    database        : process.env.DB_NAME,
});

db.connect(err => {
    if (err) {
      console.error('Database connection failed:', err);
      return;
    }
    console.log('Connected to MySQL database');
});

// Add middleware after imports
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

// Sign Up Endpoint
app.post('/api/signup', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: 'All fields are required!' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    const query = `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`;
    
    db.query(query, [username, email, hash], (err, result) => {
      if (err) {
        console.error('Database error:', err);
        if (err.code === 'ER_DUP_ENTRY') {
          const field = err.sqlMessage.includes('email') ? 'Email' : 'Username';
          return res.status(400).json({ message: `${field} already exists.` });
        }
        return res.status(500).json({ message: 'Error saving user to database' });
      }

      const userId = result.insertId;
      const token = jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
      
      console.log('Creating response with:', { userId, hasToken: !!token });
      
      return res.status(201).json({ 
        message: 'User registered successfully!',
        token,
        userId,
        user: {
          id: userId,
          username,
          email
        }
      });
    });
  } catch (error) {
    console.error('Signup error:', error);
    return res.status(500).json({ message: 'Error during signup process' });
  }
});

// Sign In Endpoint
app.post('/api/signin', (req, res) => {
  const { email, password } = req.body;

  // Check if the email and password are provided
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  // Query to find the user by email
  const query = `SELECT * FROM users WHERE email = ?`;
  db.query(query, [email], async (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });

    if (results.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = results[0];  // Assuming the first result is the correct user
    console.log('User fetched from DB:', user);  // Log user data to verify

    // Verify password using bcrypt
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid password' });
    }

    // Generate a JWT token
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    console.log('Generated JWT token:', token); // Log token for debugging
    
    res.json({
      message: 'Sign-in successful',
      token: token
    });
  });
});

// Create a new note
app.post('/api/notes', (req, res) => {
  const { user_id, title, description } = req.body;
  const query = 'INSERT INTO notes (user_id, title, description, created_at) VALUES (?, ?, ?, NOW())';
  db.query(query, [user_id, title, description], (err, result) => {
    if (err) {
      console.error('Error creating note:', err);
      res.status(500).send('Server error');
      return;
    }
    const newNoteId = result.insertId;
    const selectQuery = 'SELECT * FROM notes WHERE note_id = ?';
    db.query(selectQuery, [newNoteId], (err, results) => {
      if (err) {
        console.error('Error fetching new note:', err);
        res.status(500).send('Server error');
        return;
      }
      res.status(201).send(results[0]);
    });
  });
});

// Fetch notes for a user
app.get('/api/notes/:user_id', (req, res) => {
  const { user_id } = req.params;
  const query = 'SELECT note_id, title, description, created_at FROM notes WHERE user_id = ?';
  db.query(query, [user_id], (err, results) => {
    if (err) {
      console.error('Error fetching notes:', err);
      res.status(500).send('Server error');
      return;
    }
    res.status(200).send(results);
  });
});

// Fetch user details
app.get('/api/users/:user_id', verifyToken, (req, res) => {
  const { user_id } = req.params;
  
  const query = 'SELECT id, username, email FROM users WHERE id = ?';
  
  db.query(query, [user_id], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ message: 'Database error' });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.status(200).json(results[0]);
  });
});

// Delete a note
app.delete('/api/notes/:note_id', (req, res) => {
  const { note_id } = req.params;
  const query = 'DELETE FROM notes WHERE note_id = ?';
  db.query(query, [note_id], (err, result) => {
    if (err) {
      console.error('Error deleting note:', err);
      res.status(500).send('Server error');
      return;
    }
    res.status(200).send({ message: 'Note deleted' });
  });
});

// Update a note
app.put('/api/notes/:note_id', (req, res) => {
  const { note_id } = req.params;
  const { title, description } = req.body;
  const query = 'UPDATE notes SET title = ?, description = ? WHERE note_id = ?';
  db.query(query, [title, description, note_id], (err, result) => {
    if (err) {
      console.error('Error updating note:', err);
      res.status(500).send('Server error');
      return;
    }
    res.status(200).send({ message: 'Note updated' });
  });
});

// Fetch User Data API
app.get('/api/user/:id', (req, res) => {
  const { id } = req.params;

  // Query to find the user by id
  const query = `SELECT name, email FROM users WHERE id = ?`;
  db.query(query, [id], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ message: 'Database error' });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = results[0];  // Assuming the first result is the correct user
    console.log('Sending user data:', user); // Log the user data being sent
    res.json(user);
  });
});

// Add new route for current user
app.get('/api/user', verifyToken, (req, res) => {
  const query = `SELECT id, username, email FROM users WHERE id = ?`;
  
  db.query(query, [req.user.id], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ message: 'Database error' });
    }

    if (!results || results.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = results[0];
    console.log('Sending user data:', user);
    
    return res.status(200).json({
      id: user.id,
      username: user.username,
      email: user.email
    });
  });
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});