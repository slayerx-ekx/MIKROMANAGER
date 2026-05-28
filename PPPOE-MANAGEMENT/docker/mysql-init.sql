CREATE DATABASE IF NOT EXISTS mikrotik_ppp;
USE mikrotik_ppp;
SET time_zone = '+07:00';

-- Users table (untuk login & user management)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    full_name VARCHAR(100),
    role ENUM('super_admin','admin','teknisi','viewer') DEFAULT 'teknisi',
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Routers table
CREATE TABLE IF NOT EXISTS routers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    api_port INT DEFAULT 8728,
    snmp_user VARCHAR(100) DEFAULT '',
    snmp_port INT DEFAULT 161,
    username VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_router_active_name (is_active, name),
    INDEX idx_router_ip (ip_address),
    INDEX idx_router_updated_at (updated_at)
);

-- PPP Secrets/Users table
CREATE TABLE IF NOT EXISTS ppp_secrets (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    router_id INT NOT NULL,
    username VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    interface_name VARCHAR(255),
    profile VARCHAR(100),
    service VARCHAR(50) DEFAULT 'pppoe',
    local_address VARCHAR(45),
    remote_address VARCHAR(45),
    uptime VARCHAR(100),
    last_link_down VARCHAR(100),
    last_link_up VARCHAR(100),
    status ENUM('online', 'offline') DEFAULT 'offline',
    caller_id VARCHAR(100),
    bytes_in BIGINT DEFAULT 0,
    bytes_out BIGINT DEFAULT 0,
    last_seen TIMESTAMP NULL,
    synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (router_id) REFERENCES routers(id) ON DELETE CASCADE,
    UNIQUE KEY uniq_router_user (router_id, username),
    INDEX idx_router_id (router_id),
    INDEX idx_status (status),
    INDEX idx_profile (profile)
);

-- Traffic history table
CREATE TABLE IF NOT EXISTS traffic_history (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    router_id INT NOT NULL,
    interface_name VARCHAR(100) NOT NULL,
    rx_bps BIGINT DEFAULT 0,
    tx_bps BIGINT DEFAULT 0,
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (router_id) REFERENCES routers(id) ON DELETE CASCADE,
    INDEX idx_router_interface (router_id, interface_name),
    INDEX idx_recorded_at (recorded_at)
);

-- Sync settings table
CREATE TABLE IF NOT EXISTS sync_settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    auto_sync_enabled BOOLEAN DEFAULT TRUE,
    sync_interval_seconds INT DEFAULT 60,
    last_sync_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Sync logs table
CREATE TABLE IF NOT EXISTS sync_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    router_id INT,
    router_name VARCHAR(100),
    status ENUM('success', 'failed') NOT NULL,
    message TEXT,
    duration_ms INT,
    records_synced INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_created_at (created_at)
);

CREATE TABLE IF NOT EXISTS user_nms_layouts (
    user_id INT PRIMARY KEY,
    layout_json LONGTEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS nms_layout_global (
    id INT PRIMARY KEY,
    layout_json LONGTEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS nms_history_samples (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    router_id INT NOT NULL,
    if_index INT NOT NULL,
    interface_name VARCHAR(255),
    interface_label VARCHAR(255),
    oper_status VARCHAR(32) DEFAULT 'unknown',
    rx_bps BIGINT DEFAULT 0,
    tx_bps BIGINT DEFAULT 0,
    sampled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_nms_router_if_time (router_id, if_index, sampled_at),
    INDEX idx_nms_sampled_at (sampled_at)
);

-- Default data
-- Password: admin123
INSERT INTO users (username, password, full_name, role, is_active) VALUES
('admin', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Administrator', 'super_admin', 1)
ON DUPLICATE KEY UPDATE id=id;

INSERT INTO sync_settings (auto_sync_enabled, sync_interval_seconds) VALUES (TRUE, 60)
ON DUPLICATE KEY UPDATE id=id;

INSERT INTO nms_layout_global (id, layout_json) VALUES (1, '{"widgets":[],"layout_mode":"auto","history":{}}')
ON DUPLICATE KEY UPDATE id=id;
