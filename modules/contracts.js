/*jslint node: true */
'use strict';
const db = require('ocore/db');
const chash = require('ocore/chash');
const conf = require('ocore/conf');

function get(hash) {
	return new Promise((resolve) => {
		db.query(`SELECT hash, unit, arbiter_address, status, status_change_date FROM arbiter_contracts_arbstore WHERE hash=?`, [hash], function(rows) {
			var row = rows.length ? rows[0] : null;
			resolve(row);
		});
	});
}

async function queryBalance(contract_hash) {
	let rows = await db.query(
		`SELECT outputs.asset, SUM(outputs.amount) AS balance
		FROM arbiter_contracts_arbstore
		JOIN units USING(unit)
		JOIN outputs USING(address)
		WHERE is_spent=0 AND sequence='good' AND is_stable=1 AND arbiter_contracts_arbstore.hash=?
		GROUP BY asset`, [contract_hash]);
	rows.forEach(async row => {
		let amount = row.amount;
		let arbiter = await arbiters.getByHash(row.hash);
		device.sendMessageToDevice(arbiter.device_address, 'text', texts.received_payment(amount));
	});
}

function insertNew(hash, unit, arbiter, amount, status) {
	return new Promise((resolve) => {
		db.query(`INSERT INTO arbiter_contracts_arbstore (hash, unit, arbiter_address, amount, status) VALUES (?, ?, ?, ?, ?)`, [hash, unit, arbiter.address, amount, status], resolve);
	});
}

function updateStatus(hash, status) {
	return new Promise((resolve) => {
		db.query(`UPDATE arbiter_contracts_arbstore SET status=?, status_change_date=date('now') WHERE hash=?`, [status, hash], resolve);
	});
}

exports.get = get;
exports.insertNew = insertNew;
exports.updateStatus = updateStatus;