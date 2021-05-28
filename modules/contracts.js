/*jslint node: true */
'use strict';
const db = require('ocore/db');
const conf = require('ocore/conf');
const arbiter_contract = require('ocore/arbiter_contract');

async function get(hash) {
	let rows = await db.query(`SELECT arbstore_arbiter_contracts.hash, arbstore_arbiter_contracts.unit, arbiter_address, shared_address, amount, asset, status, status_change_date, plaintiff_pairing_code, peer_pairing_code, service_fee, contract, side1_address, side2_address, winner_side, plaintiff_side
		FROM arbstore_arbiter_contracts 
		WHERE hash=?`, [hash]);
	var row = rows.length ? rows[0] : null;
	if (row && row.contract) {
		row.contract = JSON.parse(row.contract);
		row.is_hash_valid = arbiter_contract.getHash({
			title: row.contract.title,
			text: row.contract.text,
			creation_date: row.contract.creation_date,
			arbiter_address: row.arbiter_address,
			amount: row.amount,
			asset: row.asset
		}) === row.hash;
		row.side1_attested = false;
		row.side2_attested = false;
		if (conf.trustedAttestorAddresses && conf.trustedAttestorAddresses.length) {
			let payloads = await db.query(`SELECT payload FROM messages
				JOIN unit_authors USING(unit) WHERE address IN(?) AND app='attestation'`, [conf.trustedAttestorAddresses]);
			payloads.forEach(payload => {
				let json = JSON.parse(payload.payload);
				if (json.address === row.side1_address)
					row.side1_attested = true;
				if (json.address === row.side2_address)
					row.side2_attested = true;
			});
		}
	}
	return row;
}

async function queryBalance(contract_hash) {
	let rows = await db.query(
		`SELECT outputs.asset, SUM(outputs.amount) AS amount
		FROM arbstore_arbiter_contracts
		JOIN units USING(unit)
		JOIN unit_authors USING(unit)
		JOIN outputs USING(address)
		WHERE is_spent=0 AND sequence='good' AND is_stable=1 AND arbstore_arbiter_contracts.hash=?
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
	return db.query(`INSERT INTO arbstore_arbiter_contracts (hash, unit, shared_address, arbiter_address, amount, asset, status, side1_address, side2_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, [hash, unit, shared_address, arbiter.address, amount, asset, status, side1_address, side2_address]);
}

function updateStatus(hash, status) {
	return db.query(`UPDATE arbstore_arbiter_contracts SET status=?, status_change_date=date('now') WHERE hash=?`, [status, hash]);
}

function updateField(field, hash, value) {
	if (!["plaintiff_pairing_code", "peer_pairing_code", "service_fee", "service_fee_address", "appeal_fee_address", "contract", "winner_side", "plaintiff_side", "amount", "asset"].includes(field))
		throw new Error("wrong field for updateField method");
	return db.query(`UPDATE arbstore_arbiter_contracts SET ${field}=? WHERE hash=?`, [value, hash]);
}

async function getAllByStatus(status) {
	let rows = await db.query(`SELECT * FROM arbstore_arbiter_contracts WHERE status IN (?) ORDER BY status_change_date DESC`, [status]);
	rows.forEach(row => {
		row.contract = JSON.parse(row.contract);
	})
	return rows;
}

exports.get = get;
exports.queryBalance = queryBalance;
exports.insertNew = insertNew;
exports.updateStatus = updateStatus;
exports.updateField = updateField
exports.getAllByStatus = getAllByStatus;