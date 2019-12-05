/*jslint node: true */
'use strict';
const db = require('ocore/db');
const chash = require('ocore/chash');
const balances = require('ocore/balances');
const conf = require('ocore/conf');

function insertNew(hash, unit, arbiter_address, status){
	return new Promise((resolve) => {
		db.query(`INSERT INTO arbiter_contracts (hash, unit, arbiter_address, status) VALUES (?, ?, ?, ?)`, [hash, unit, arbiter_address, status], resolve);
	});
}

function updateStatus(hash, status){
	return new Promise((resolve) => {
		db.query(`UPDATE contracts SET status=?, status_change_date=date('now') WHERE hash=?`, [status, hash], resolve);
	});
}

exports.insertNew = insertNew;
exports.updateStatus = updateStatus;