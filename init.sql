CREATE TABLE IF NOT EXISTS domains (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(253) NOT NULL UNIQUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS scans (
    id CHAR(36) PRIMARY KEY,
    domain_id INT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'complete',
    started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at DATETIME NULL,
    error TEXT NULL,
    CONSTRAINT fk_scans_domain FOREIGN KEY (domain_id) REFERENCES domains(id),
    INDEX ix_scans_domain_started (domain_id, started_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS stage_runs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    scan_id CHAR(36) NOT NULL,
    stage VARCHAR(40) NOT NULL,
    status VARCHAR(30) NOT NULL,
    count INT NOT NULL DEFAULT 0,
    log_tail TEXT NOT NULL,
    started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at DATETIME NULL,
    CONSTRAINT fk_stage_runs_scan FOREIGN KEY (scan_id) REFERENCES scans(id),
    INDEX ix_stage_runs_scan (scan_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS subdomains (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    scan_id CHAR(36) NOT NULL,
    name VARCHAR(253) NOT NULL,
    sources JSON NOT NULL,
    first_seen_scan_id CHAR(36) NULL,
    CONSTRAINT fk_subdomains_scan FOREIGN KEY (scan_id) REFERENCES scans(id),
    CONSTRAINT fk_subdomains_first_seen FOREIGN KEY (first_seen_scan_id) REFERENCES scans(id),
    CONSTRAINT uq_subdomain_scan_name UNIQUE (scan_id, name),
    INDEX ix_subdomains_name (name)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS live_hosts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    scan_id CHAR(36) NOT NULL,
    url VARCHAR(2048) NOT NULL,
    host VARCHAR(253) NOT NULL,
    status_code INT NULL,
    title VARCHAR(512) NULL,
    CONSTRAINT fk_live_hosts_scan FOREIGN KEY (scan_id) REFERENCES scans(id),
    INDEX ix_live_hosts_scan (scan_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS screenshots (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    scan_id CHAR(36) NOT NULL,
    host VARCHAR(253) NOT NULL,
    file_path VARCHAR(1024) NOT NULL,
    CONSTRAINT fk_screenshots_scan FOREIGN KEY (scan_id) REFERENCES scans(id),
    INDEX ix_screenshots_scan (scan_id)
) ENGINE=InnoDB;