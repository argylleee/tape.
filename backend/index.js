const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const port = 5000;

app.use(cors());
app.use(express.json());

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

// Sign Up Endpoint
app.post('/api/signup', (req, res) => {
  const { username, email, password } = req.body;

  console.log('Received signup request:', { username, email, password }); // Log incoming request

  // Validate input
  if (!username || !email || !password) {
    console.log('Validation failed, missing fields');
    return res.status(400).json({ message: 'All fields are required!' });
  }

  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      console.log('Error hashing password:', err); // Log the error
      return res.status(500).json({ message: 'Error hashing password' });
    }

    // Insert user data into the database
    const query = `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`;

    db.query(query, [username, email, hash], (err, result) => {
      if (err) {
        // Handle duplicate entry error
        if (err.code === 'ER_DUP_ENTRY') {
          console.log('Duplicate entry detected:', err.sqlMessage);

          // Determine the conflicting field
          const field = err.sqlMessage.includes('email') ? 'Email' : 'Username';

          return res.status(400).json({ message: `${field} is already taken.` });
        }

        console.log('Error saving user to database:', err);
        return res.status(500).json({ message: 'Error saving user to database' });
      }

      console.log('User registered successfully:', { userId: result.insertId });
      res.status(201).json({ message: 'User registered successfully!' });
    });
  });
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

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});