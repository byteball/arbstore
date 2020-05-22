/*jslint node: true */
'use strict';
const db = require('ocore/db');
const chash = require('ocore/chash');
const conf = require('ocore/conf');

function get(hash) {
	return new Promise((resolve) => {
		db.query(`SELECT hash, unit, arbiter_address, shared_address, amount, asset, status, status_change_date, plaintiff_pairing_code, service_fee FROM arbiter_contracts_arbstore WHERE hash=?`, [hash], function(rows) {
			var row = rows.length ? rows[0] : null;
			resolve(row);
		});
	});
}

async function queryBalance(contract_hash) {
	let rows = await db.query(
		`SELECT outputs.asset, SUM(outputs.amount) AS amount
		FROM arbiter_contracts_arbstore
		JOIN units USING(unit)
		JOIN unit_authors USING(unit)
		JOIN outputs USING(address)
		WHERE is_spent=0 AND sequence='good' AND is_stable=1 AND arbiter_contracts_arbstore.hash=?
		GROUP BY outputs.asset`, [contract_hash]);
	let balances = {};
	rows.forEach(row => {
		if (!balances[row.asset])
			balances[row.asset] = 0;
		balances[row.asset] += row.amount;
	});
	return balances;
}

function insertNew(hash, unit, shared_address, arbiter, amount, asset, status) {
	return new Promise((resolve) => {
		db.query(`INSERT INTO arbiter_contracts_arbstore (hash, unit, shared_address, arbiter_address, amount, asset, status) VALUES (?, ?, ?, ?, ?, ?, ?)`, [hash, unit, shared_address, arbiter.address, amount, asset, status], resolve);
	});
}

function updateStatus(hash, status) {
	return new Promise((resolve) => {
		db.query(`UPDATE arbiter_contracts_arbstore SET status=?, status_change_date=date('now') WHERE hash=?`, [status, hash], resolve);
	});
}

function updateField(field, hash, value) {
	if (!["plaintiff_pairing_code", "service_fee", "service_fee_address"].includes(field))
		throw new Error("wrong field for updateField method");
	return new Promise((resolve) => {
		db.query(`UPDATE arbiter_contracts_arbstore SET ${field}=? WHERE hash=?`, [value, hash], resolve);
	});
}

exports.get = get;
exports.queryBalance = queryBalance;
exports.insertNew = insertNew;
exports.updateStatus = updateStatus;
exports.updateField = updateField