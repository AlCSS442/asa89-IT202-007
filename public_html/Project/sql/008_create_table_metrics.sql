CREATE TABLE cve_cvss_metrics (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(20),
    cvss_version VARCHAR(10),
    base_score DECIMAL(3, 1),
    base_severity VARCHAR(50),
    FOREIGN KEY (cve_id) REFERENCES `Project-cveId`(cveId)
);
