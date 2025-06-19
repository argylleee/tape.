-- Drop existing tables if they exist
DROP TABLE IF EXISTS rate_attempts;
DROP TABLE IF EXISTS rate_limits;

-- Create rate_limits table with all required columns
CREATE TABLE rate_limits (
    identifier VARCHAR(255) PRIMARY KEY,
    locked_until DATETIME,
    attempt_count INT DEFAULT 0,
    lockout_period INT DEFAULT 60,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Create rate_attempts table with all required columns
CREATE TABLE rate_attempts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    identifier VARCHAR(255),
    attempt_time DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_identifier_time (identifier, attempt_time)
); 