const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const xss = require('xss-clean');
const hpp = require('hpp');
const nodemailer = require('nodemailer');
const axios = require('axios');
const crypto = require('crypto');
require('dotenv').config({ path: __dirname + '/.env' });

const app = express();
const port = 5000;

// Configure CORS
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Optimize middleware order and configuration
app.use(express.json({ limit: '10mb' }));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  crossOriginOpenerPolicy: { policy: "unsafe-none" },
  contentSecurityPolicy: false // Disable CSP for development
}));
app.use(xss());
app.use(hpp());

if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.header('x-forwarded-proto') !== 'https') {
      res.redirect(`https://${req.header('host')}${req.url}`);
    } else {
      next();
    }
  });
}

// Rate limiting implementation
const signinLimiter = async (req, res, next) => {
  try {
    const identifier = req.body.identifier;
    const now = Date.now();

    // First, get both username and email for the identifier
    const getUserQuery = `
      SELECT username, email 
      FROM users 
      WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)
    `;

    pool.query(getUserQuery, [identifier, identifier], async (err, userResults) => {
      if (err) {
        console.error('Error getting user info:', err);
        return next();
      }

      if (userResults.length === 0) {
        // If user not found, just track the attempt for the identifier
        return trackAttempt(identifier, next);
      }

      const { username, email } = userResults[0];

      // Check if either username or email is locked out
      const checkLockQuery = `
        SELECT locked_until, attempt_count 
        FROM rate_limits 
        WHERE identifier IN (?, ?)
      `;
      
      pool.query(checkLockQuery, [username, email], async (err, results) => {
        if (err) {
          console.error('Error checking lock status:', err);
          return next();
        }

        // Find the latest locked_until (if any)
        let latestLock = null;
        let currentAttemptCount = 0;
        for (const result of results) {
          if (result.locked_until && new Date(result.locked_until) > new Date()) {
            if (!latestLock || new Date(result.locked_until) > new Date(latestLock)) {
              latestLock = result.locked_until;
            }
          }
          // Get the highest attempt count
          if (result.attempt_count > currentAttemptCount) {
            currentAttemptCount = result.attempt_count;
          }
        }

        // If there's an active lock, return the lockout message
        if (latestLock) {
          const lockTime = new Date(latestLock);
          const now = new Date();
          const minutesRemaining = Math.ceil((lockTime - now) / (1000 * 60));
          
          return res.status(429).json({
            success: false,
            message: `Too many failed attempts. Please wait ${minutesRemaining} minute${minutesRemaining !== 1 ? 's' : ''} before trying again.`,
            attemptCount: currentAttemptCount,
            lockoutPeriod: minutesRemaining,
            lockedUntil: lockTime
          });
        }

        // Get attempts within the last hour
        const getAttemptCountQuery = `
          SELECT COUNT(*) as attempt_count
          FROM rate_attempts 
          WHERE identifier IN (?, ?)
          AND attempt_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)
        `;
        
        pool.query(getAttemptCountQuery, [username, email], (err, countResults) => {
          if (err) {
            console.error('Error getting attempt count:', err);
            return next();
          }

          const currentAttemptCount = countResults[0]?.attempt_count || 0;
          const newAttemptCount = currentAttemptCount + 1;

          // Progressive lockout periods: 1min, 3min, 5min, 10min, 15min, 30min, 40min, 60min
          const lockoutPeriods = [1, 3, 5, 10, 15, 30, 40, 60];
          
          // Calculate the current period based on the attempt count
          let periodIndex = -1;
          let attemptsInCurrentWindow = newAttemptCount % 5; // Track attempts within current window
          
          if (newAttemptCount >= 5 && attemptsInCurrentWindow === 0) {
            periodIndex = Math.floor((newAttemptCount - 5) / 5); // Calculate which period we're in
            if (periodIndex >= lockoutPeriods.length) {
              periodIndex = lockoutPeriods.length - 1; // Cap at maximum period
            }
          }

          // Only set lockout if we've reached the threshold
          const nowDate = new Date();
          let lockUntil = null;
          if (periodIndex >= 0) {
            // If already locked, escalate from now, not from previous locked_until
            lockUntil = new Date(nowDate.getTime() + (lockoutPeriods[periodIndex] * 60 * 1000));
          }

          // Update both username and email with the same attempt count and lockout
          const updatePromises = [username, email].map(id => {
            return new Promise((resolve, reject) => {
              const updateQuery = `
                INSERT INTO rate_limits (identifier, attempt_count, locked_until) 
                VALUES (?, ?, ?) 
                ON DUPLICATE KEY UPDATE 
                  attempt_count = VALUES(attempt_count),
                  locked_until = VALUES(locked_until)
              `;
              
              pool.query(updateQuery, [id, newAttemptCount, lockUntil], (err) => {
                if (err) {
                  console.error('Error updating rate limit:', err);
                  reject(err);
                } else {
                  resolve();
                }
              });
            });
          });

          Promise.all(updatePromises)
            .then(() => {
              // Add current attempt to rate_attempts
              const insertAttemptQuery = 'INSERT INTO rate_attempts (identifier, attempt_time) VALUES (?, FROM_UNIXTIME(?/1000))';
              pool.query(insertAttemptQuery, [identifier, Date.now()], (err) => {
                if (err) {
                  console.error('Error inserting attempt:', err);
                }
                // If locked, always return the current lockout message
                if (periodIndex >= 0) {
                  const waitMinutes = lockoutPeriods[periodIndex];
                  const message = waitMinutes === 1 ? 
                    'Too many failed attempts. Please wait 1 minute before trying again.' :
                    `Too many failed attempts. Please wait ${waitMinutes} minutes before trying again.`;
                  return res.status(429).json({
                    success: false,
                    message: message,
                    attemptCount: newAttemptCount,
                    lockoutPeriod: waitMinutes,
                    attemptsInCurrentWindow: attemptsInCurrentWindow,
                    lockedUntil: lockUntil
                  });
                }
                next();
              });
            })
            .catch(err => {
              console.error('Error updating rate limits:', err);
              next();
            });
        });
      });
    });
  } catch (error) {
    console.error('Rate limit error:', error);
    next();
  }
};

// Helper function to track attempts for unknown identifiers
const trackAttempt = (identifier, next) => {
  const now = Date.now();
  const insertAttemptQuery = 'INSERT INTO rate_attempts (identifier, attempt_time) VALUES (?, FROM_UNIXTIME(?/1000))';
  pool.query(insertAttemptQuery, [identifier, now], (err) => {
    if (err) {
      console.error('Error inserting attempt:', err);
    }
    next();
  });
};

// Optimize database pool
const pool = mysql.createPool({
  connectionLimit: 20, // Increased connection limit
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  charset: 'utf8mb4',
  collation: 'utf8mb4_unicode_ci',
  waitForConnections: true,
  queueLimit: 0
});

// Test the connection
pool.getConnection((err, connection) => {
  if (err) {
    console.error('Database connection failed:', err);
    return;
  }
  console.log('Connected to MySQL database');
  connection.release();
});

// Create rate limiting tables if they don't exist
const createRateLimitsTables = async () => {
  const rateLimitsQuery = `
    CREATE TABLE IF NOT EXISTS rate_limits (
      identifier VARCHAR(255) PRIMARY KEY,
      locked_until DATETIME,
      attempt_count INT DEFAULT 0,
      lockout_period INT DEFAULT 60,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )
  `;
  
  const rateAttemptsQuery = `
    CREATE TABLE IF NOT EXISTS rate_attempts (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      identifier VARCHAR(255),
      attempt_time DATETIME,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_identifier_time (identifier, attempt_time)
    )
  `;
  
  try {
    await new Promise((resolve, reject) => {
      pool.query(rateLimitsQuery, (err) => {
        if (err) {
          console.error('Error creating rate_limits table:', err);
          reject(err);
        } else {
          console.log('Rate limits table created successfully');
          resolve();
        }
      });
    });

    await new Promise((resolve, reject) => {
      pool.query(rateAttemptsQuery, (err) => {
        if (err) {
          console.error('Error creating rate_attempts table:', err);
          reject(err);
        } else {
          console.log('Rate attempts table created successfully');
          resolve();
        }
      });
    });

    console.log('Rate limiting tables initialized successfully');
  } catch (error) {
    console.error('Error initializing rate limiting tables:', error);
  }
};

// Cleanup old rate limit entries every hour
const cleanupRateLimits = async () => {
  try {
    // Remove rate limit entries that are no longer locked and have no recent attempts
    const cleanupQuery = `
      DELETE FROM rate_limits 
      WHERE (locked_until IS NULL OR locked_until < NOW()) 
      AND identifier NOT IN (
        SELECT DISTINCT identifier 
        FROM rate_attempts 
        WHERE attempt_time > DATE_SUB(NOW(), INTERVAL 24 HOUR)
      )
    `;
    
    await new Promise((resolve, reject) => {
      pool.query(cleanupQuery, (err) => {
        if (err) {
          console.error('Error cleaning up rate limits:', err);
          reject(err);
        } else {
          resolve();
        }
      });
    });

    // Remove old rate attempts
    const cleanupAttemptsQuery = `
      DELETE FROM rate_attempts 
      WHERE attempt_time < DATE_SUB(NOW(), INTERVAL 24 HOUR)
    `;
    
    await new Promise((resolve, reject) => {
      pool.query(cleanupAttemptsQuery, (err) => {
        if (err) {
          console.error('Error cleaning up rate attempts:', err);
          reject(err);
        } else {
          resolve();
        }
      });
    });
  } catch (error) {
    console.error('Error in cleanup:', error);
  }
};

// Run cleanup every hour
setInterval(cleanupRateLimits, 60 * 60 * 1000);

// Call this when the server starts
createRateLimitsTables();

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

// Input validation middleware for signup
const validateSignup = [
  body('username')
    .trim()
    .isLength({ min: 3 })
    .withMessage('Username must be at least 3 characters long')
    .escape()
    .custom(async (value) => {
      // Check if username exists
      return new Promise((resolve, reject) => {
        pool.query('SELECT id FROM users WHERE username = ?', [value], (err, results) => {
          if (err) {
            reject(new Error('Database error'));
          }
          if (results.length > 0) {
            reject(new Error('Username already exists'));
          }
          resolve(true);
        });
      });
    }),
  body('email')
    .isEmail()
    .withMessage('Please enter a valid email')
    .normalizeEmail()
    .custom(async (value) => {
      // Check if email exists
      return new Promise((resolve, reject) => {
        pool.query('SELECT id FROM users WHERE email = ?', [value], (err, results) => {
          if (err) {
            reject(new Error('Database error'));
          }
          if (results.length > 0) {
            reject(new Error('Email already exists'));
          }
          resolve(true);
        });
      });
    }),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character')
    .custom((value, { req }) => {
      if (value === req.body.username) {
        throw new Error('Password cannot be the same as username');
      }
      return true;
    }),
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords do not match');
      }
      return true;
    }),
  body('hcaptchaToken')
    .notEmpty()
    .withMessage('hCaptcha token is required'),
  body('role')
    .optional()
    .isIn(['user', 'admin'])
    .withMessage('Invalid role')
];

// Input validation middleware for signin
const validateSignin = [
  body('identifier')
    .notEmpty()
    .withMessage('Username or email is required')
    .trim()
    .escape(),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

// Input validation middleware for note creation
const validateNote = [
  body('title').optional().trim(),
  body('content_html').optional().trim(),
  body('user_id').notEmpty().withMessage('User ID is required')
];

// hCaptcha configuration
console.log('DEBUG: HCAPTCHA_SECRET_KEY:', process.env.HCAPTCHA_SECRET_KEY);
const HCAPTCHA_SECRET_KEY = process.env.HCAPTCHA_SECRET_KEY || 'ES_f747e9fd9920459d8c2b6b9ef8904344';

// Verify hCaptcha token
async function verifyHcaptcha(token) {
  try {
    console.log('Verifying hCaptcha token:', token);
    const response = await axios.post(
      'https://hcaptcha.com/siteverify',
      new URLSearchParams({
        secret: HCAPTCHA_SECRET_KEY,
        response: token
      }).toString(),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    console.log('hCaptcha verification response:', response.data);
    if (!response.data.success) {
      console.error('hCaptcha verification failed:', response.data['error-codes']);
      return response.data; // Return the full response for debugging
    }
    return response.data;
  } catch (error) {
    console.error('hCaptcha verification error:', error.response?.data || error.message);
    console.error('Full error object:', error);
    return { success: false, error: error.response?.data || error.message };
  }
}

// Check NOTE_ENCRYPTION_KEY validity at startup
if (!process.env.NOTE_ENCRYPTION_KEY || process.env.NOTE_ENCRYPTION_KEY.length !== 64) {
  console.error('FATAL: NOTE_ENCRYPTION_KEY is missing or not 64 characters long!');
  console.error('Current value:', process.env.NOTE_ENCRYPTION_KEY);
  process.exit(1);
} else {
  console.log('NOTE_ENCRYPTION_KEY loaded, length:', process.env.NOTE_ENCRYPTION_KEY.length);
}

// AES-256-CBC encryption utilities for notes
const NOTE_ENCRYPTION_KEY = process.env.NOTE_ENCRYPTION_KEY || 'ed32e980627b9e889cb9a15df88140e5e40bf66a8558e10b641510d26ba1d50f'; // 32 bytes fallback
const ALGORITHM = 'aes-256-cbc';
function encrypt(text) {
  // Debug log for key value and length
  console.log('ENCRYPT: NOTE_ENCRYPTION_KEY length:', NOTE_ENCRYPTION_KEY.length, 'value:', NOTE_ENCRYPTION_KEY);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(NOTE_ENCRYPTION_KEY, 'hex'), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}
function decrypt(text) {
  // If text is empty or not a string, return as is
  if (!text || typeof text !== 'string') return text;
  // If text does not contain a colon, treat as unencrypted
  if (!text.includes(':')) return text;
  try {
    const [ivHex, encrypted] = text.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(NOTE_ENCRYPTION_KEY, 'hex'), iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) {
    // If decryption fails, return the original text
    return text;
  }
}

// Sign Up Endpoint
app.post('/api/signup', validateSignup, async (req, res) => {
  console.log('=== BACKEND DEBUG ===');
  console.log('Request headers:', req.headers);
  console.log('Request body:', req.body);
  console.log('Request body type:', typeof req.body);
  console.log('Request body keys:', Object.keys(req.body || {}));
  
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log('Validation errors:', errors.array());
    return res.status(400).json({ 
      success: false,
      errors: errors.array().map(err => ({
        field: err.path,
        message: err.msg
      }))
    });
  }

  const { username, email, password, hcaptchaToken, role } = req.body;
  console.log('Extracted fields:');
  console.log('- username:', username);
  console.log('- email:', email);
  console.log('- password length:', password ? password.length : 'undefined');
  console.log('- hcaptchaToken:', hcaptchaToken ? 'present' : 'missing');
  console.log('- role:', role);
  
  const userRole = role || 'user';

  try {
    // Verify hCaptcha
    console.log('Verifying hCaptcha...');
    const isHcaptchaValid = await verifyHcaptcha(hcaptchaToken);
    console.log('hCaptcha verification result:', isHcaptchaValid);
    
    if (!isHcaptchaValid) {
      return res.status(400).json({
        success: false,
        message: 'hCaptcha verification failed'
      });
    }

    // Check if username or email already exists (redundant, but safe)
    const checkUserQuery = 'SELECT * FROM users WHERE username = ? OR email = ?';
    pool.query(checkUserQuery, [username, email], async (err, results) => {
      if (err) {
        console.error('Error checking existing user:', err);
        return res.status(500).json({
          success: false,
          message: 'Error checking existing user'
        });
      }

      if (results.length > 0) {
        return res.status(400).json({
          success: false,
          message: 'Username or email already exists'
        });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Generate verification token
      const verificationToken = jwt.sign(
        { email },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );

      // Insert new user (only required fields)
      const insertUserQuery = `
        INSERT INTO users (username, email, password, role, verification_token, is_verified)
        VALUES (?, ?, ?, ?, ?, false)
      `;
      
      pool.query(
        insertUserQuery,
        [username, email, hashedPassword, userRole, verificationToken],
        async (err, result) => {
          if (err) {
            console.error('Error creating user:', err);
            return res.status(500).json({
              success: false,
              message: 'Error creating user',
              dbError: err.message,
              dbCode: err.code,
              dbFull: JSON.stringify(err)
            });
          }

          // Send verification email
          const verificationLink = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`;
          const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Verify your email',
            html: `
              <h1>Welcome to our platform!</h1>
              <p>Please click the link below to verify your email address:</p>
              <a href="${verificationLink}">${verificationLink}</a>
              <p>This link will expire in 24 hours.</p>
            `
          };

          try {
            await transporter.sendMail(mailOptions);
          } catch (emailError) {
            console.error('Error sending verification email:', emailError);
            // Continue even if email fails
          }

          // Return token and user object (like sign-in)
          const token = jwt.sign({ id: result.insertId }, process.env.JWT_SECRET, { expiresIn: '1h' });
          res.status(201).json({
            success: true,
            message: 'User created successfully. Please check your email for verification.',
            token,
            user: {
              id: result.insertId,
              username,
              email,
              role: userRole,
              is_verified: false
            }
          });
        }
      );
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Test endpoint to check users table
app.get('/api/debug/users', (req, res) => {
  const query = 'SELECT id, username, email FROM users';
  pool.query(query, (err, results) => {
    if (err) {
      console.error('Debug query error:', err);
      return res.status(500).json({ error: 'Database error', details: err.message });
    }
    res.json({ 
      totalUsers: results.length,
      users: results 
    });
  });
});

// Sign In Endpoint with rate limiting
app.post('/api/signin', validateSignin, signinLimiter, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      success: false,
      message: errors.array()[0].msg
    });
  }

  const { identifier, password } = req.body;

  try {
    // Query to find the user by username or email
    const query = 'SELECT * FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)';
    pool.query(query, [identifier, identifier], async (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ 
          success: false,
          message: 'Database error' 
        });
      }

      if (results.length === 0) {
        return res.status(404).json({ 
          success: false,
          message: 'User not found' 
        });
      }

      const user = results[0];
      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res.status(400).json({ 
          success: false,
          message: 'Invalid password' 
        });
      }

      // If login is successful, reset the attempt count and clear lockout for both username and email
      const resetAttemptsQuery = `
        UPDATE rate_limits 
        SET attempt_count = 0, 
            locked_until = NULL 
        WHERE identifier IN (?, ?)
      `;
      
      pool.query(resetAttemptsQuery, [user.username, user.email], (err) => {
        if (err) {
          console.error('Error resetting attempt count:', err);
        }
      });

      const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
      return res.json({
        success: true,
        message: 'Sign-in successful',
        token: token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email
        }
      });
    });
  } catch (error) {
    console.error('Sign-in error:', error);
    return res.status(500).json({ 
      success: false,
      message: 'Error during sign-in process' 
    });
  }
});

// Create a new note
app.post('/api/notes', verifyToken, (req, res) => {
  const { user_id, title, description, content_html, tags } = req.body;
  if (user_id !== req.user.id) {
    return res.status(403).json({ message: 'Unauthorized to create note for this user' });
  }
  // Encrypt only title, description, and content_html
  const encTitle = encrypt(title ? title.toString().trim() : 'Untitled Note');
  const encDescription = encrypt(description ? description.toString().trim() : '');
  const encContent = encrypt(content_html ? content_html.toString().trim() : '');
  const tagsJson = JSON.stringify(Array.isArray(tags) ? tags : []); // Do not encrypt tags
  const query = 'INSERT INTO notes (user_id, title, description, content_html, tags, created_at) VALUES (?, ?, ?, ?, ?, NOW())';
  const values = [user_id, encTitle, encDescription, encContent, tagsJson];
  pool.query(query, values, (err, result) => {
    if (err) {
      console.error('Error creating note (SQL):', err);
      return res.status(500).json({ message: 'Error creating note', sqlError: err.message });
    }
    res.status(201).json({
      note_id: result.insertId,
      user_id,
      title,
      description,
      content_html,
      tags: Array.isArray(tags) ? tags : [],
      created_at: new Date().toISOString(),
      modified_at: new Date().toISOString()
    });
  });
});

// Fetch notes for a user with sorting and filtering
app.get('/api/users/:user_id/notes', verifyToken, (req, res) => {
  const { user_id } = req.params;
  const { sort_by = 'created_at', order = 'DESC', search = '', tag = '' } = req.query;
  
  console.log('Fetch notes request:', {
    params: req.params,
    query: req.query,
    user: req.user,
    headers: req.headers
  });

  // Verify that the user_id matches the authenticated user
  if (String(user_id) !== String(req.user.id)) {
    console.error('User ID mismatch:', { 
      provided: user_id, 
      authenticated: req.user.id,
      token: req.headers.authorization
    });
    return res.status(403).json({ message: 'Unauthorized to fetch notes for this user' });
  }
  
  let query = `
    SELECT note_id, title, description, content_html, tags, created_at, modified_at 
    FROM notes 
    WHERE user_id = ?
  `;
  
  const queryParams = [user_id];
  
  // Add search condition if search term is provided
  if (search) {
    query += ` AND (title LIKE ? OR description LIKE ? OR content_html LIKE ?)`;
    const searchTerm = `%${search}%`;
    queryParams.push(searchTerm, searchTerm, searchTerm);
  }
  
  // Add tag filter if tag is provided
  if (tag) {
    query += ` AND JSON_CONTAINS(tags, ?)`;
    queryParams.push(JSON.stringify(tag));
  }
  
  // Add sorting
  const validSortFields = ['created_at', 'modified_at', 'title', 'sort_order'];
  const sortField = validSortFields.includes(sort_by) ? sort_by : 'created_at';
  const sortOrder = order.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';
  query += ` ORDER BY ${sortField} ${sortOrder}`;
  
  console.log('Fetching notes with query:', query, 'params:', queryParams);
  
  pool.query(query, queryParams, (err, results) => {
    if (err) {
      console.error('Error fetching notes:', err);
      return res.status(500).json({ message: 'Error fetching notes' });
    }

    console.log('Query results:', results);

    // Decrypt all fields
    const safeResults = results.map(note => {
      let tagsArr = [];
      try { tagsArr = JSON.parse(decrypt(note.tags)); } catch (e) { tagsArr = []; }
      return {
        ...note,
        title: decrypt(note.title),
        description: decrypt(note.description),
        content_html: decrypt(note.content_html),
        tags: tagsArr
      };
    });

    console.log('Safe results:', safeResults);
    res.status(200).json({ notes: safeResults });
  });
});

// Get a single note by ID
app.get('/api/notes/:note_id', verifyToken, (req, res) => {
  const { note_id } = req.params;
  
  pool.query(
    'SELECT * FROM notes WHERE note_id = ?',
    [note_id],
    (err, results) => {
      if (err) {
        console.error('Error fetching note:', err);
        return res.status(500).json({ message: 'Error fetching note' });
      }
      
      if (results.length === 0) {
        return res.status(404).json({ message: 'Note not found' });
      }

      // Decrypt all fields
      const note = results[0];
      let tagsArr = [];
      try { tagsArr = JSON.parse(decrypt(note.tags)); } catch (e) { tagsArr = []; }
      res.json({
        ...note,
        title: decrypt(note.title),
        description: decrypt(note.description),
        content_html: decrypt(note.content_html),
        tags: tagsArr
      });
    }
  );
});

// Update a note
app.put('/api/notes/:note_id', verifyToken, (req, res) => {
  const { note_id } = req.params;
  const { title, content_html, tags, description } = req.body;
  // Encrypt only title, description, and content_html
  const encTitle = encrypt(title ? title.toString().trim() : 'Untitled Note');
  const encDescription = encrypt(description ? description.toString().trim() : '');
  const encContent = encrypt(content_html ? content_html.toString().trim() : '');
  const tagsJson = JSON.stringify(Array.isArray(tags) ? tags : []); // Do not encrypt tags
  const query = `UPDATE notes SET title = ?, description = ?, content_html = ?, tags = ?, modified_at = NOW() WHERE note_id = ?`;
  pool.query(query, [encTitle, encDescription, encContent, tagsJson, note_id], (err, result) => {
    if (err) {
      return res.status(500).json({ message: 'Error updating note' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Note not found' });
    }
    // Fetch the updated note
    pool.query('SELECT * FROM notes WHERE note_id = ?', [note_id], (err, results) => {
      if (err) {
        return res.status(500).json({ message: 'Error fetching updated note' });
      }
      const note = results[0];
      let tagsArr = [];
      try { tagsArr = JSON.parse(decrypt(note.tags)); } catch (e) { tagsArr = []; }
      res.json({
        ...note,
        title: decrypt(note.title),
        description: decrypt(note.description),
        content_html: decrypt(note.content_html),
        tags: tagsArr
      });
    });
  });
});

// Delete a note
app.delete('/api/notes/:note_id', verifyToken, (req, res) => {
  const { note_id } = req.params;
  
  pool.query('DELETE FROM notes WHERE note_id = ?', [note_id], (err, result) => {
    if (err) {
      console.error('Error deleting note:', err);
      return res.status(500).json({ message: 'Error deleting note' });
    }
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Note not found' });
    }
    
    res.json({ message: 'Note deleted successfully' });
  });
});

// Fetch user details
app.get('/api/users/:user_id', verifyToken, (req, res) => {
  const { user_id } = req.params;
  
  const query = 'SELECT id, username, email FROM users WHERE id = ?';
  
  pool.query(query, [user_id], (err, results) => {
    if (err) {
      console.error('Error fetching user:', err);
      return res.status(500).json({ message: 'Error fetching user details' });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json(results[0]);
  });
});

// Checklist endpoints
app.post('/api/checklists', verifyToken, async (req, res) => {
  const { note_id, title, items, user_id } = req.body;
  if (user_id !== req.user.id) {
    console.error('User ID mismatch:', { provided: user_id, authenticated: req.user.id });
    return res.status(403).json({ message: 'Unauthorized to create checklist for this user' });
  }
  try {
    // Encrypt checklist title
    const encTitle = encrypt(title ? title.toString().trim() : 'Untitled Checklist');
    // Create checklist
    const checklistQuery = 'INSERT INTO checklists (note_id, title) VALUES (?, ?)';
    pool.query(checklistQuery, [note_id, encTitle], (err, result) => {
      if (err) {
        console.error('Error creating checklist:', err);
        return res.status(500).json({ success: false, message: 'Error creating checklist' });
      }
      const checklistId = result.insertId;
      // Create checklist items
      if (items && items.length > 0) {
        // Encrypt item content
        const itemValues = items.map(item => [checklistId, encrypt(item.content), item.is_completed || false]);
        const itemsQuery = 'INSERT INTO checklist_items (checklist_id, content, is_completed) VALUES ?';
        pool.query(itemsQuery, [itemValues], (err, result) => {
          if (err) {
            console.error('Error creating checklist items:', err, 'itemValues:', itemValues);
            return res.status(500).json({ success: false, message: 'Error creating checklist items', sqlError: err.message });
          }
          // Fetch the created checklist with items
          const getChecklistQuery = `
            SELECT c.*, 
              JSON_ARRAYAGG(
                JSON_OBJECT(
                  'id', ci.id,
                  'content', ci.content,
                  'is_completed', ci.is_completed,
                  'created_at', ci.created_at,
                  'modified_at', ci.modified_at
                )
              ) as items
            FROM checklists c
            LEFT JOIN checklist_items ci ON c.id = ci.checklist_id
            WHERE c.id = ?
            GROUP BY c.id
          `;
          pool.query(getChecklistQuery, [checklistId], (err, results) => {
            if (err) {
              console.error('Error fetching created checklist:', err);
              return res.status(500).json({ success: false, message: 'Error fetching created checklist' });
            }
            const checklist = results[0];
            try {
              checklist.title = decrypt(checklist.title);
              checklist.items = JSON.parse(checklist.items).map(item => ({
                ...item,
                content: decrypt(item.content)
              }));
            } catch (e) {
              checklist.items = [];
            }
            res.status(201).json({ 
              success: true, 
              message: 'Checklist created successfully',
              checklist
            });
          });
        });
      } else {
        res.status(201).json({ 
          success: true, 
          message: 'Checklist created successfully',
          checklist: {
            id: checklistId,
            note_id,
            title,
            items: []
          }
        });
      }
    });
  } catch (error) {
    console.error('Error in checklist creation:', error);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/checklists/:noteId', verifyToken, async (req, res) => {
  const { noteId } = req.params;
  try {
    const query = `
      SELECT c.*, 
        JSON_ARRAYAGG(
          JSON_OBJECT(
            'id', ci.id,
            'content', ci.content,
            'is_completed', ci.is_completed,
            'created_at', ci.created_at,
            'modified_at', ci.modified_at
          )
        ) as items
      FROM checklists c
      LEFT JOIN checklist_items ci ON c.id = ci.checklist_id
      WHERE c.note_id = ?
      GROUP BY c.id
    `;
    pool.query(query, [noteId], (err, results) => {
      if (err) {
        console.error('Error fetching checklist:', err);
        return res.status(500).json({ message: 'Error fetching checklist' });
      }
      if (results.length === 0) {
        return res.status(404).json({ message: 'Checklist not found' });
      }
      const checklist = results[0];
      try {
        checklist.title = decrypt(checklist.title);
        checklist.items = JSON.parse(checklist.items).map(item => ({
          ...item,
          content: decrypt(item.content)
        }));
      } catch (e) {
        checklist.items = [];
      }
      res.json(checklist);
    });
  } catch (error) {
    console.error('Error in checklist fetch:', error);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Update a checklist
app.put('/api/checklists/:noteId', verifyToken, async (req, res) => {
  const { noteId } = req.params;
  const { title, items } = req.body;
  console.log('PUT /api/checklists/:noteId', { noteId, title, items });
  try {
    pool.getConnection((err, connection) => {
      if (err) {
        console.error('Error getting connection:', err);
        return res.status(500).json({ message: 'Database error' });
      }
      connection.beginTransaction(err => {
        if (err) {
          connection.release();
          console.error('Error starting transaction:', err);
          return res.status(500).json({ message: 'Database error' });
        }
        const getChecklistQuery = 'SELECT id FROM checklists WHERE note_id = ?';
        connection.query(getChecklistQuery, [noteId], (err, results) => {
          if (err) {
            console.error('Error getting checklist:', err);
            return connection.rollback(() => {
              connection.release();
              return res.status(500).json({ message: 'Error getting checklist' });
            });
          }
          if (results.length === 0) {
            console.error('Checklist not found for noteId:', noteId);
            return connection.rollback(() => {
              connection.release();
              return res.status(404).json({ message: 'Checklist not found' });
            });
          }
          const checklistId = results[0].id;
          console.log('Found checklistId:', checklistId);
          // Encrypt checklist title
          const encTitle = encrypt(title ? title.toString().trim() : 'Untitled Checklist');
          const updateChecklistQuery = 'UPDATE checklists SET title = ? WHERE id = ?';
          connection.query(updateChecklistQuery, [encTitle, checklistId], (err) => {
            if (err) {
              console.error('Error updating checklist:', err);
              return connection.rollback(() => {
                connection.release();
                return res.status(500).json({ message: 'Error updating checklist' });
              });
            }
            const deleteItemsQuery = 'DELETE FROM checklist_items WHERE checklist_id = ?';
            connection.query(deleteItemsQuery, [checklistId], (err) => {
              if (err) {
                console.error('Error deleting checklist items:', err);
                return connection.rollback(() => {
                  connection.release();
                  return res.status(500).json({ message: 'Error updating checklist items' });
                });
              }
              if (items && items.length > 0) {
                // Encrypt item content
                const itemValues = items.map(item => [checklistId, encrypt(item.content), item.is_completed || false]);
                const insertItemsQuery = 'INSERT INTO checklist_items (checklist_id, content, is_completed) VALUES ?';
                console.log('Inserting items:', itemValues);
                connection.query(insertItemsQuery, [itemValues], (err, insertResult) => {
                  if (err) {
                    console.error('Error inserting checklist items:', err);
                    return connection.rollback(() => {
                      connection.release();
                      return res.status(500).json({ message: 'Error updating checklist items' });
                    });
                  }
                  console.log('Inserted items result:', insertResult);
                  connection.commit(err => {
                    if (err) {
                      console.error('Error committing transaction:', err);
                      return connection.rollback(() => {
                        connection.release();
                        return res.status(500).json({ message: 'Database error' });
                      });
                    }
                    const getUpdatedChecklistQuery = `
                      SELECT c.*, 
                        JSON_ARRAYAGG(
                          JSON_OBJECT(
                            'id', ci.id,
                            'content', ci.content,
                            'is_completed', ci.is_completed,
                            'created_at', ci.created_at,
                            'modified_at', ci.modified_at
                          )
                        ) as items
                      FROM checklists c
                      LEFT JOIN checklist_items ci ON c.id = ci.checklist_id
                      WHERE c.id = ?
                      GROUP BY c.id
                    `;
                    connection.query(getUpdatedChecklistQuery, [checklistId], (err, results) => {
                      if (err) {
                        console.error('Error fetching updated checklist:', err);
                        connection.release();
                        return res.status(500).json({ message: 'Error fetching updated checklist' });
                      }
                      const updatedChecklist = results[0];
                      try {
                        updatedChecklist.title = decrypt(updatedChecklist.title);
                        updatedChecklist.items = JSON.parse(updatedChecklist.items).map(item => ({
                          ...item,
                          content: decrypt(item.content)
                        }));
                      } catch (e) {
                        updatedChecklist.items = [];
                      }
                      connection.release();
                      res.json({ 
                        success: true, 
                        message: 'Checklist updated successfully',
                        checklist: updatedChecklist
                      });
                    });
                  });
                });
              } else {
                connection.commit(err => {
                  if (err) {
                    console.error('Error committing transaction:', err);
                    return connection.rollback(() => {
                      connection.release();
                      return res.status(500).json({ message: 'Database error' });
                    });
                  }
                  connection.release();
                  res.json({ 
                    success: true, 
                    message: 'Checklist updated successfully',
                    checklist: {
                      note_id: noteId,
                      title,
                      items: []
                    }
                  });
                });
              }
            });
          });
        });
      });
    });
  } catch (error) {
    console.error('Error in checklist update:', error);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Debug endpoint to check database connection and users
app.get('/api/debug/db', async (req, res) => {
  try {
    // Check database connection
    const connection = await new Promise((resolve, reject) => {
      pool.getConnection((err, conn) => {
        if (err) reject(err);
        else resolve(conn);
      });
    });

    // Get all users
    const users = await new Promise((resolve, reject) => {
      connection.query('SELECT id, username, email, created_at FROM users', (err, results) => {
        if (err) reject(err);
        else resolve(results);
      });
    });

    // Get database info
    const dbInfo = await new Promise((resolve, reject) => {
      connection.query('SELECT DATABASE() as db_name, VERSION() as version', (err, results) => {
        if (err) reject(err);
        else resolve(results[0]);
      });
    });

    connection.release();

    res.json({
      status: 'success',
      database: {
        name: dbInfo.db_name,
        version: dbInfo.version,
        connection: 'OK'
      },
      users: {
        count: users.length,
        list: users
      }
    });
  } catch (error) {
    console.error('Debug endpoint error:', error);
    res.status(500).json({
      status: 'error',
      message: error.message,
      stack: error.stack
    });
  }
});

// Test the connection and verify database schema
const verifyDatabaseSchema = async () => {
  try {
    const connection = await new Promise((resolve, reject) => {
      pool.getConnection((err, conn) => {
        if (err) reject(err);
        else resolve(conn);
      });
    });

    // Create users table if it doesn't exist
    await new Promise((resolve, reject) => {
      connection.query(`
        CREATE TABLE IF NOT EXISTS users (
          id INT AUTO_INCREMENT PRIMARY KEY,
          username VARCHAR(255) NOT NULL UNIQUE,
          email VARCHAR(255) NOT NULL UNIQUE,
          password VARCHAR(255) NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
      `, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    // Create notes table if it doesn't exist
    await new Promise((resolve, reject) => {
      connection.query(`
        CREATE TABLE IF NOT EXISTS notes (
          note_id INT AUTO_INCREMENT PRIMARY KEY,
          user_id INT NOT NULL,
          title VARCHAR(255) NOT NULL,
          description TEXT,
          content_html TEXT,
          tags JSON,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
      `, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    // Create checklists table if it doesn't exist
    await new Promise((resolve, reject) => {
      connection.query(`
        CREATE TABLE IF NOT EXISTS checklists (
          id INT AUTO_INCREMENT PRIMARY KEY,
          note_id INT NOT NULL,
          title VARCHAR(255),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          FOREIGN KEY (note_id) REFERENCES notes(note_id) ON DELETE CASCADE
        )
      `, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    // Create checklist_items table if it doesn't exist
    await new Promise((resolve, reject) => {
      connection.query(`
        CREATE TABLE IF NOT EXISTS checklist_items (
          id INT AUTO_INCREMENT PRIMARY KEY,
          checklist_id INT NOT NULL,
          content TEXT,
          is_completed BOOLEAN DEFAULT FALSE,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          FOREIGN KEY (checklist_id) REFERENCES checklists(id) ON DELETE CASCADE
        )
      `, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    console.log('Database schema verified successfully');
    connection.release();
  } catch (error) {
    console.error('Error verifying database schema:', error);
  }
};

// Debug endpoint to get current lockout status and attempt count
app.get('/api/debug/rate-limit-status', (req, res) => {
  const identifier = req.query.identifier;
  if (!identifier) {
    return res.status(400).json({ success: false, message: 'Identifier is required' });
  }
  // Get both username and email for the identifier
  const getUserQuery = `
    SELECT username, email 
    FROM users 
    WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)
  `;
  pool.query(getUserQuery, [identifier, identifier], (err, userResults) => {
    if (err) {
      return res.status(500).json({ success: false, message: 'Database error', error: err.message });
    }
    if (userResults.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    const { username, email } = userResults[0];
    // Get lockout info
    const lockQuery = `
      SELECT identifier, locked_until, attempt_count 
      FROM rate_limits 
      WHERE identifier IN (?, ?)
    `;
    pool.query(lockQuery, [username, email], (err, lockResults) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Database error', error: err.message });
      }
      res.json({
        success: true,
        rate_limits: lockResults
      });
    });
  });
});

// Change Password Endpoint
app.post('/api/change-password', verifyToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.user.id;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ message: 'All fields are required.' });
  }

  // Get user from DB
  pool.query('SELECT password FROM users WHERE id = ?', [userId], async (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error.' });
    if (results.length === 0) return res.status(404).json({ message: 'User not found.' });

    const user = results[0];
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Current password is incorrect.' });

    // Check if new password is the same as current
    const isSame = await bcrypt.compare(newPassword, user.password);
    if (isSame) return res.status(400).json({ message: 'New password must be different from the current password.' });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    pool.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, userId], (err) => {
      if (err) return res.status(500).json({ message: 'Failed to update password.' });
      res.json({ message: 'Password updated successfully.' });
    });
  });
});

// Global error handling middleware (should be placed after all routes)
app.use((err, req, res, next) => {
  console.error('Global error handler:', err.stack || err);
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? (err.stack || err.message) : undefined
  });
});

// Catch unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  // Optionally, log to a file or external service
});

// Catch uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception thrown:', err);
  // Optionally, log to a file or external service
  // Do not exit the process automatically
});

// Start the server
app.listen(port, async () => {
  console.log(`Server is running on port ${port}`);
  await verifyDatabaseSchema();
  await createRateLimitsTables();
});