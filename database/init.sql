CREATE DATABASE cvedb;

USE cvedb;

CREATE TABLE cves (
    cve_id VARCHAR(100) PRIMARY KEY,
    description TEXT,
    base_score FLOAT,
    last_modified DATE
);
