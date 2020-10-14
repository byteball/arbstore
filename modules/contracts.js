/*jslint node: true */
'use strict';
const db = require('ocore/db');
const conf = require('ocore/conf');
const arbiter_contract = require('ocore/arbiter_contract');

function get(hash) {
	return new Promise((resolve) => {
		db.query(`SELECT hash, unit, arbiter_address, shared_address, amount, asset, status, status_change_date, plaintiff_pairing_code, peer_pairing_code, service_fee, contract, side1_address, side2_address, winner FROM arbiter_contracts_arbstore WHERE hash=?`, [hash], function(rows) {
			var row = rows.length ? rows[0] : null;
			if (row && row.contract) {
				row.contract = JSON.parse(row.contract);
				row.is_hash_valid = arbiter_contract.getHash({
					title: row.contract.title,
					text: row.contract.text,
					creation_date: row.contract.creation_date,
					arbiter_address: row.arbiter_address,
					amount: row.amount
				}) === row.hash;
			}
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

function insertNew(hash, unit, shared_address, arbiter, amount, asset, status, side1_address, side2_address) {
	return new Promise((resolve) => {
		db.query(`INSERT INTO arbiter_contracts_arbstore (hash, unit, shared_address, arbiter_address, amount, asset, status, side1_address, side2_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, [hash, unit, shared_address, arbiter.address, amount, asset, status, side1_address, side2_address], resolve);
	});
}

function updateStatus(hash, status) {
	return new Promise((resolve) => {
		db.query(`UPDATE arbiter_contracts_arbstore SET status=?, status_change_date=date('now') WHERE hash=?`, [status, hash], resolve);
	});
}

function updateField(field, hash, value) {
	if (!["plaintiff_pairing_code", "peer_pairing_code", "service_fee", "service_fee_address", "appeal_fee_address", "contract", "winner"].includes(field))
		throw new Error("wrong field for updateField method");
	return new Promise((resolve) => {
		db.query(`UPDATE arbiter_contracts_arbstore SET ${field}=? WHERE hash=?`, [value, hash], resolve);
	});
}

function getAllByStatus(status) {
	return new Promise((resolve) => {
		db.query(`SELECT * FROM arbiter_contracts_arbstore WHERE status=?`, [status], function(rows) {
			rows.forEach(row => {
				row.contract = JSON.parse(row.contract);
			})
			resolve(rows);
		});
	});
}

exports.get = get;
exports.queryBalance = queryBalance;
exports.insertNew = insertNew;
exports.updateStatus = updateStatus;
exports.updateField = updateField
exports.getAllByStatus = getAllByStatus;