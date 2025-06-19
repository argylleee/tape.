-- Add a 'role' column to the users table for RBAC support
ALTER TABLE users ADD COLUMN role VARCHAR(50) DEFAULT 'user'; 