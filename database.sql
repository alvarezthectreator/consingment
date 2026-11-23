CREATE DATABASE IF NOT EXISTS cadence_tracking
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE cadence_tracking;

CREATE TABLE IF NOT EXISTS shipments (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  tracking_code VARCHAR(64) NOT NULL,
  unique_id VARCHAR(64) NOT NULL,
  shipment_number VARCHAR(64) NOT NULL,
  status VARCHAR(40) NOT NULL,
  last_updated DATETIME NOT NULL,
  courier_name VARCHAR(100) NOT NULL,
  delivery_address VARCHAR(500) NOT NULL,
  item_description VARCHAR(255) NOT NULL,
  estimated_delivery DATE NOT NULL,
  sender VARCHAR(150) NOT NULL,
  receiver VARCHAR(150) NOT NULL,
  weight_kg DECIMAL(8, 2) NOT NULL,
  size_m3 DECIMAL(8, 3) NOT NULL,
  parcel_info VARCHAR(255) NOT NULL,
  truck_number VARCHAR(32) NOT NULL,
  driver_name VARCHAR(150) NOT NULL,
  driver_phone VARCHAR(40) NOT NULL,
  truck_state VARCHAR(60) NOT NULL,
  events JSON NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_shipments_tracking_code (tracking_code)
) ENGINE=InnoDB;

INSERT INTO shipments (
  tracking_code, unique_id, shipment_number, status, last_updated, courier_name,
  delivery_address, item_description, estimated_delivery, sender, receiver,
  weight_kg, size_m3, parcel_info, truck_number, driver_name, driver_phone,
  truck_state, events
) VALUES (
  '8pnp2qn2h2034hjf',
  '8pnp2qn2h2034hjf',
  'NP 421 2441 5551',
  'In Progress',
  '2024-01-12 15:50:00',
  'JUSTIN',
  'Vulytsya Tarasa Shevchenka, 1Б, Vyzhnytsya, Chernivtsi Oblast, Ukraine, 59200',
  'Children''s cartoon quartz watch',
  '2025-01-11',
  'Not displayed',
  'Vyzhnytsya, Ukraine',
  51.00,
  3.200,
  'Shipment parcel',
  '#H72',
  'Dariy Kuruchuk',
  '+380 68 120 91 80',
  'In Motion',
  '[
    {"occurred_at":"2024-01-12 15:16:00","title":"Delivery order created","description":"thefinals.com","state":"complete"},
    {"occurred_at":"2024-01-13 11:11:00","title":"JUSTIN created order","description":"label and update for 5 Pages","state":"complete"},
    {"occurred_at":"2024-01-13 18:24:00","title":"In transit to destination","description":"","state":"current"}
  ]'
);

CREATE TABLE IF NOT EXISTS admin_users (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username VARCHAR(60) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_admin_users_username (username)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS invoices (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  invoice_number VARCHAR(64) NOT NULL,
  tracking_code VARCHAR(64) NULL,
  customer_name VARCHAR(150) NOT NULL,
  customer_email VARCHAR(190) NULL,
  description VARCHAR(500) NOT NULL,
  amount DECIMAL(12, 2) NOT NULL,
  currency CHAR(3) NOT NULL DEFAULT 'USD',
  status ENUM('draft', 'sent', 'paid', 'overdue', 'cancelled') NOT NULL DEFAULT 'draft',
  issue_date DATE NOT NULL,
  due_date DATE NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_invoices_invoice_number (invoice_number),
  KEY idx_invoices_tracking_code (tracking_code)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS payment_gateway_settings (
  method_key VARCHAR(32) NOT NULL,
  provider VARCHAR(100) NOT NULL,
  display_name VARCHAR(100) NOT NULL,
  description VARCHAR(255) NOT NULL DEFAULT '',
  payment_details TEXT NOT NULL,
  checkout_url VARCHAR(500) NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 0,
  sort_order SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (method_key)
) ENGINE=InnoDB;

INSERT IGNORE INTO payment_gateway_settings
  (method_key, provider, display_name, description, payment_details, checkout_url, enabled, sort_order)
VALUES
  ('crypto', 'Crypto wallet', 'Crypto', 'Bitcoin, Ethereum, USDT', '', NULL, 0, 1),
  ('bank', 'Bank transfer', 'Bank transfer', 'Direct bank payment', '', NULL, 0, 2),
  ('card', 'Hosted card checkout', 'Card', 'Visa, Mastercard, American Express', '', NULL, 0, 3);