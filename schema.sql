CREATE DATABASE IF NOT EXISTS lumenfield;
USE lumenfield;

CREATE TABLE IF NOT EXISTS devices (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  ip VARCHAR(45) NOT NULL,
  mac VARCHAR(17) NULL,
  hostname VARCHAR(255) NULL,
  vendor VARCHAR(80) NULL,
  role_hint VARCHAR(80) NULL,
  first_seen DATETIME NOT NULL,
  last_seen DATETIME NOT NULL,
  times_seen INT NOT NULL DEFAULT 1,
  last_ports VARCHAR(160) NULL,
  last_evidence VARCHAR(255) NULL,
  UNIQUE KEY uniq_ip (ip)
);

CREATE TABLE IF NOT EXISTS sightings (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  device_id BIGINT NOT NULL,
  seen_at DATETIME NOT NULL,
  neigh_state VARCHAR(24) NULL,
  ports VARCHAR(160) NULL,
  evidence VARCHAR(255) NULL,
  KEY device_seen (device_id, seen_at),
  CONSTRAINT fk_sighting_device FOREIGN KEY (device_id) REFERENCES devices(id)
);
