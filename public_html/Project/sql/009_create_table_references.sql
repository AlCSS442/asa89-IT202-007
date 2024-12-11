CREATE TABLE cve_references (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(20),
    url VARCHAR(255),
    FOREIGN KEY (cve_id) REFERENCES `Project-cveId`(cveId)
);
