const mysql = require('mysql');
require('dotenv').config();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

const checkRateLimits = async () => {
  try {
    // Check rate_limits table
    const rateLimitsQuery = 'SELECT * FROM rate_limits';
    const rateLimitsResults = await new Promise((resolve, reject) => {
      pool.query(rateLimitsQuery, (err, results) => {
        if (err) reject(err);
        else resolve(results);
      });
    });
    console.log('\nRate Limits Table:');
    console.log(JSON.stringify(rateLimitsResults, null, 2));

    // Check rate_attempts table
    const rateAttemptsQuery = 'SELECT * FROM rate_attempts ORDER BY attempt_time DESC LIMIT 10';
    const rateAttemptsResults = await new Promise((resolve, reject) => {
      pool.query(rateAttemptsQuery, (err, results) => {
        if (err) reject(err);
        else resolve(results);
      });
    });
    console.log('\nRecent Rate Attempts:');
    console.log(JSON.stringify(rateAttemptsResults, null, 2));

    process.exit(0);
  } catch (error) {
    console.error('Error checking rate limits:', error);
    process.exit(1);
  }
};

checkRateLimits(); 