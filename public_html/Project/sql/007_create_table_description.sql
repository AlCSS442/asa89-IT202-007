CREATE TABLE cve_descriptions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(50),
    lang VARCHAR(10),
    description_value TEXT,
    FOREIGN KEY (cve_id) REFERENCES `Project-cveId`(cveId)
);
