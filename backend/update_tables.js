const mysql = require('mysql');
require('dotenv').config();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

const updateTables = async () => {
  try {
    // Drop existing tables
    await new Promise((resolve, reject) => {
      pool.query('DROP TABLE IF EXISTS rate_attempts', (err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    await new Promise((resolve, reject) => {
      pool.query('DROP TABLE IF EXISTS rate_limits', (err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    // Create rate_limits table
    await new Promise((resolve, reject) => {
      const query = `
        CREATE TABLE rate_limits (
          identifier VARCHAR(255) PRIMARY KEY,
          locked_until DATETIME,
          attempt_count INT DEFAULT 0,
          lockout_period INT DEFAULT 60,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
      `;
      pool.query(query, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    // Create rate_attempts table
    await new Promise((resolve, reject) => {
      const query = `
        CREATE TABLE rate_attempts (
          id BIGINT AUTO_INCREMENT PRIMARY KEY,
          identifier VARCHAR(255),
          attempt_time DATETIME,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          INDEX idx_identifier_time (identifier, attempt_time)
        )
      `;
      pool.query(query, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    console.log('Tables updated successfully');
    process.exit(0);
  } catch (error) {
    console.error('Error updating tables:', error);
    process.exit(1);
  }
};

updateTables(); 