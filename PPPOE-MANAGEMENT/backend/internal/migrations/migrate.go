package migrations

import (
	"log"

	"github.com/jmoiron/sqlx"
)

func AutoMigrate(db *sqlx.DB) error {
	log.Println("Running database migrations...")

	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INT AUTO_INCREMENT PRIMARY KEY,
			username VARCHAR(100) NOT NULL UNIQUE,
			password VARCHAR(255) NOT NULL,
			full_name VARCHAR(100),
			role VARCHAR(20) DEFAULT 'teknisi',
			is_active BOOLEAN DEFAULT TRUE,
			last_login TIMESTAMP NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS routers (
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
		)`,
		`CREATE TABLE IF NOT EXISTS ppp_secrets (
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
			status VARCHAR(10) DEFAULT 'offline',
			caller_id VARCHAR(100),
			bytes_in BIGINT DEFAULT 0,
			bytes_out BIGINT DEFAULT 0,
			last_seen TIMESTAMP NULL,
			synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			UNIQUE KEY uniq_router_user (router_id, username),
			INDEX idx_router_id (router_id),
			INDEX idx_status (status),
			INDEX idx_profile (profile)
		)`,
		`CREATE TABLE IF NOT EXISTS traffic_history (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			router_id INT NOT NULL,
			interface_name VARCHAR(100) NOT NULL,
			rx_bps BIGINT DEFAULT 0,
			tx_bps BIGINT DEFAULT 0,
			recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_router_interface (router_id, interface_name),
			INDEX idx_recorded_at (recorded_at)
		)`,
		`CREATE TABLE IF NOT EXISTS sync_settings (
			id INT AUTO_INCREMENT PRIMARY KEY,
			auto_sync_enabled BOOLEAN DEFAULT TRUE,
			sync_interval_seconds INT DEFAULT 60,
			last_sync_at TIMESTAMP NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS sync_logs (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			router_id INT,
			router_name VARCHAR(100),
			status VARCHAR(10) NOT NULL,
			message TEXT,
			duration_ms INT,
			records_synced INT DEFAULT 0,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_created_at (created_at)
		)`,
		`CREATE TABLE IF NOT EXISTS troubleshoot_logs (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			level VARCHAR(20) NOT NULL DEFAULT 'info',
			source VARCHAR(80) NOT NULL DEFAULT 'system',
			scope VARCHAR(120) NOT NULL DEFAULT 'general',
			message TEXT,
			details LONGTEXT,
			router_id INT NULL,
			router_name VARCHAR(120) DEFAULT '',
			router_ip VARCHAR(45) DEFAULT '',
			olt_id INT NULL,
			olt_name VARCHAR(120) DEFAULT '',
			olt_ip_address VARCHAR(45) DEFAULT '',
			onu_interface VARCHAR(120) DEFAULT '',
			serial_number VARCHAR(120) DEFAULT '',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_troubleshoot_created_at (created_at),
			INDEX idx_troubleshoot_source_level (source, level),
			INDEX idx_troubleshoot_router_id (router_id),
			INDEX idx_troubleshoot_olt_id (olt_id),
			INDEX idx_troubleshoot_serial_number (serial_number)
		)`,
		`CREATE TABLE IF NOT EXISTS user_nms_layouts (
			user_id INT PRIMARY KEY,
			layout_json LONGTEXT NOT NULL,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS nms_layout_global (
			id INT PRIMARY KEY,
			layout_json LONGTEXT NOT NULL,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS user_monitoring_layouts (
			user_id INT PRIMARY KEY,
			layout_json LONGTEXT NOT NULL,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS nms_history_samples (
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
		)`,
		`ALTER TABLE routers ADD COLUMN snmp_user VARCHAR(100) DEFAULT ''`,
		`ALTER TABLE routers ADD COLUMN snmp_port INT DEFAULT 161`,
		`ALTER TABLE routers ADD INDEX idx_router_active_name (is_active, name)`,
		`ALTER TABLE routers ADD INDEX idx_router_ip (ip_address)`,
		`ALTER TABLE routers ADD INDEX idx_router_updated_at (updated_at)`,
		`ALTER TABLE nms_history_samples ADD COLUMN interface_label VARCHAR(255)`,
		`ALTER TABLE nms_history_samples ADD COLUMN oper_status VARCHAR(32) DEFAULT 'unknown'`,
		`ALTER TABLE nms_history_samples ADD INDEX idx_nms_router_if_time (router_id, if_index, sampled_at)`,
		`ALTER TABLE nms_history_samples ADD INDEX idx_nms_sampled_at (sampled_at)`,
		`ALTER TABLE ppp_secrets ADD COLUMN interface_name VARCHAR(255)`,
		`ALTER TABLE ppp_secrets ADD COLUMN last_link_down VARCHAR(100)`,
		`ALTER TABLE ppp_secrets ADD COLUMN last_link_up VARCHAR(100)`,
		`ALTER TABLE troubleshoot_logs ADD COLUMN details LONGTEXT`,
		`ALTER TABLE troubleshoot_logs ADD COLUMN router_id INT NULL`,
		`ALTER TABLE troubleshoot_logs ADD COLUMN router_name VARCHAR(120) DEFAULT ''`,
		`ALTER TABLE troubleshoot_logs ADD COLUMN router_ip VARCHAR(45) DEFAULT ''`,
		`ALTER TABLE troubleshoot_logs ADD COLUMN olt_id INT NULL`,
		`ALTER TABLE troubleshoot_logs ADD COLUMN olt_name VARCHAR(120) DEFAULT ''`,
		`ALTER TABLE troubleshoot_logs ADD COLUMN olt_ip_address VARCHAR(45) DEFAULT ''`,
		`ALTER TABLE troubleshoot_logs ADD COLUMN onu_interface VARCHAR(120) DEFAULT ''`,
		`ALTER TABLE troubleshoot_logs ADD COLUMN serial_number VARCHAR(120) DEFAULT ''`,
		`ALTER TABLE troubleshoot_logs ADD INDEX idx_troubleshoot_created_at (created_at)`,
		`ALTER TABLE troubleshoot_logs ADD INDEX idx_troubleshoot_source_level (source, level)`,
		`ALTER TABLE troubleshoot_logs ADD INDEX idx_troubleshoot_router_id (router_id)`,
		`ALTER TABLE troubleshoot_logs ADD INDEX idx_troubleshoot_olt_id (olt_id)`,
		`ALTER TABLE troubleshoot_logs ADD INDEX idx_troubleshoot_serial_number (serial_number)`,
		`INSERT IGNORE INTO sync_settings (id, auto_sync_enabled, sync_interval_seconds) VALUES (1, TRUE, 60)`,
		`INSERT IGNORE INTO nms_layout_global (id, layout_json) VALUES (1, '[]')`,
		`INSERT IGNORE INTO users (username, password, full_name, role, is_active) VALUES ('admin', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Administrator', 'super_admin', 1)`,
		`UPDATE users SET role='super_admin' WHERE username='admin' AND (role='operator' OR role='admin' OR role='')`,
	}

	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			log.Printf("Migration note: %v", err)
		}
	}

	log.Println("Migrations done")
	return nil
}
