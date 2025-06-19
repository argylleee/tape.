const mysql = require('mysql');
require('dotenv').config();

// Debug environment variables
console.log('Database Configuration:');
console.log('Host:', process.env.DB_HOST);
console.log('User:', process.env.DB_USER);
console.log('Database:', process.env.DB_NAME);
console.log('Password length:', process.env.DB_PASSWORD ? process.env.DB_PASSWORD.length : 0);

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

const clearRateLimits = async () => {
  try {
    // Clear rate_attempts table
    await new Promise((resolve, reject) => {
      pool.query('TRUNCATE TABLE rate_attempts', (err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    // Clear rate_limits table
    await new Promise((resolve, reject) => {
      pool.query('TRUNCATE TABLE rate_limits', (err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    console.log('Rate limit data cleared successfully');
    process.exit(0);
  } catch (error) {
    console.error('Error clearing rate limit data:', error);
    process.exit(1);
  }
};

clearRateLimits(); 