CREATE TABLE IF NOT EXISTS arbiters (
	address CHAR(32) NOT NULL PRIMARY KEY,
	device_address CHAR(33) NOT NULL UNIQUE,
	hash CHAR(44) NOT NULL UNIQUE,
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	deposit_address CHAR(32) NOT NULL,
	enabled TINYINT NOT NULL DEFAULT 1,
	visible TINYINT NOT NULL DEFAULT 1,
	info TEXT NULL,
	announce_unit CHAR(44) NULL UNIQUE,
	FOREIGN KEY (device_address) REFERENCES correspondent_devices(device_address),
	FOREIGN KEY (deposit_address) REFERENCES my_addresses(address)
);
-- query separator
CREATE TABLE IF NOT EXISTS arbiter_contracts_arbstore (
	hash CHAR(44) NOT NULL PRIMARY KEY,
	unit CHAR(44) NULL UNIQUE,
	shared_address CHAR(32) NOT NULL,
	arbiter_address CHAR(32) NOT NULL,
	amount BIGINT NOT NULL,
	asset CHAR(44) NULL,
	status TEXT CHECK (status IN('active', 'dispute_requested', 'in_dispute', 'resolved')) NOT NULL DEFAULT 'active',
	status_change_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	service_fee INT NULL,
	service_fee_address CHAR(32) NULL,
	plaintiff_pairing_code VARCHAR(200) NULL,
	FOREIGN KEY (arbiter_address) REFERENCES arbiters(address),
	FOREIGN KEY (unit) REFERENCES units(unit)
);