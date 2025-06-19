const mysql = require('mysql');
require('dotenv').config();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

const debugRateLimits = async () => {
  try {
    // Show table structure
    console.log('\n=== Table Structure ===');
    const showTablesQuery = 'SHOW TABLES';
    const tables = await new Promise((resolve, reject) => {
      pool.query(showTablesQuery, (err, results) => {
        if (err) reject(err);
        else resolve(results);
      });
    });
    console.log('Tables:', tables);

    // Show rate_limits structure
    const showRateLimitsQuery = 'DESCRIBE rate_limits';
    const rateLimitsStructure = await new Promise((resolve, reject) => {
      pool.query(showRateLimitsQuery, (err, results) => {
        if (err) reject(err);
        else resolve(results);
      });
    });
    console.log('\nRate Limits Structure:', JSON.stringify(rateLimitsStructure, null, 2));

    // Show rate_attempts structure
    const showRateAttemptsQuery = 'DESCRIBE rate_attempts';
    const rateAttemptsStructure = await new Promise((resolve, reject) => {
      pool.query(showRateAttemptsQuery, (err, results) => {
        if (err) reject(err);
        else resolve(results);
      });
    });
    console.log('\nRate Attempts Structure:', JSON.stringify(rateAttemptsStructure, null, 2));

    // Show all rate limits
    const rateLimitsQuery = 'SELECT * FROM rate_limits';
    const rateLimitsResults = await new Promise((resolve, reject) => {
      pool.query(rateLimitsQuery, (err, results) => {
        if (err) reject(err);
        else resolve(results);
      });
    });
    console.log('\nAll Rate Limits:', JSON.stringify(rateLimitsResults, null, 2));

    // Show recent attempts
    const rateAttemptsQuery = 'SELECT * FROM rate_attempts ORDER BY attempt_time DESC LIMIT 10';
    const rateAttemptsResults = await new Promise((resolve, reject) => {
      pool.query(rateAttemptsQuery, (err, results) => {
        if (err) reject(err);
        else resolve(results);
      });
    });
    console.log('\nRecent Attempts:', JSON.stringify(rateAttemptsResults, null, 2));

    // Show attempt counts by identifier
    const attemptCountsQuery = `
      SELECT identifier, COUNT(*) as attempt_count 
      FROM rate_attempts 
      GROUP BY identifier 
      ORDER BY attempt_count DESC
    `;
    const attemptCounts = await new Promise((resolve, reject) => {
      pool.query(attemptCountsQuery, (err, results) => {
        if (err) reject(err);
        else resolve(results);
      });
    });
    console.log('\nAttempt Counts by Identifier:', JSON.stringify(attemptCounts, null, 2));

    process.exit(0);
  } catch (error) {
    console.error('Error debugging rate limits:', error);
    process.exit(1);
  }
};

debugRateLimits(); 