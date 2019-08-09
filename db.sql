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