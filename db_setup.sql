-- ============================================================
-- Netad CCTV Security System – Database Schema
-- Run this once on your Railway PostgreSQL instance
-- ============================================================

-- Users table (login accounts)
CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    username        VARCHAR(50)  UNIQUE NOT NULL,
    password_hash   VARCHAR(64)  NOT NULL,
    salt            VARCHAR(32)  NOT NULL,
    role            VARCHAR(20)  DEFAULT 'viewer',   -- 'admin' | 'viewer'
    is_locked       BOOLEAN      DEFAULT FALSE,
    failed_attempts INT          DEFAULT 0,
    last_login      TIMESTAMP,
    created_at      TIMESTAMP    DEFAULT NOW()
);

-- Network security events (populated by detector.py)
CREATE TABLE IF NOT EXISTS audit_logs (
    id          SERIAL PRIMARY KEY,
    timestamp   TIMESTAMP    DEFAULT NOW(),
    ip_address  VARCHAR(45),
    action      VARCHAR(200),
    status      VARCHAR(20)   -- 'Critical' | 'Alert' | 'Info'
);

-- Login / access attempt history (populated by main.py)
CREATE TABLE IF NOT EXISTS login_logs (
    id          SERIAL PRIMARY KEY,
    timestamp   TIMESTAMP    DEFAULT NOW(),
    username    VARCHAR(50),
    ip_address  VARCHAR(45),
    status      VARCHAR(20),  -- 'Success' | 'Failed'
    reason      VARCHAR(200)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_audit_timestamp   ON audit_logs  (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_status      ON audit_logs  (status);
CREATE INDEX IF NOT EXISTS idx_login_timestamp   ON login_logs  (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_login_username    ON login_logs  (username);
