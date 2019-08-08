/*jslint node: true */
'use strict';
const db = require('ocore/db');
const chash = require('ocore/chash');
const headlessWallet = require('headless-obyte');
const balances = require('ocore/balances');
const conf = require('ocore/conf');

function create(address, device_address){
	return new Promise((resolve) => {
		headlessWallet.issueNextMainAddress(async deposit_address => {
			let hash = chash.getChash160(address + device_address + deposit_address + Date.now().toString());
			await db.query(`INSERT INTO arbiters (address, device_address, hash, deposit_address) VALUES (?, ?, ?, ?)`, [address, device_address, hash, deposit_address]);
			resolve([hash, deposit_address]);
		});
		
	});
}

function updateAddress(address, device_address){
	return new Promise((resolve) => {
		db.query(`UPDATE arbiters SET address=? WHERE device_address=?`, [address, device_address], resolve);
	});
}

const select_arbiter_sql = `SELECT address, 
		arbiters.device_address, 
		arbiters.hash, 
		arbiters.creation_date, 
		arbiters.deposit_address, 
		arbiters.enabled, 
		arbiters.visible, 
		arbiters.info, 
		arbiters.announce_unit, 
		cd.name
	FROM arbiters 
	JOIN correspondent_devices AS cd USING (device_address)
`;

function getByDeviceAddress(device_address) {
	return new Promise(async resolve => {
		let rows = await db.query(select_arbiter_sql + `WHERE device_address=?`, [device_address]);
		if (rows.length)
			return resolve(parseInfo(rows[0]));
		resolve(null);
	});
}

function getByHash(hash) {
	return new Promise(async resolve => {
		let rows = await db.query(select_arbiter_sql + `WHERE hash=?`, [hash]);
		if (rows.length)
			return resolve(parseInfo(rows[0]));
		resolve(null);
	});
}


function parseInfo(row) {
	row.info = JSON.parse(row.info);
	if (!row.info) row.info = {tags: [], languages: []};
	return row;
}

function updateInfo(hash, info, visible){
	return new Promise((resolve) => {
		db.query(`UPDATE arbiters SET info=?, visible=? WHERE hash=?`, [JSON.stringify(info), visible, hash], resolve);
	});
}

function setEnabled(hash, enabled) {
	return new Promise((resolve) => {
		db.query(`UPDATE arbiters SET enabled=? WHERE hash=?`, [!!enabled, hash], resolve);
	});	
}

function getDepositBalance(hash) {
	return new Promise(async resolve => {
		let arbiter = await getByHash(hash);
		balances.readBalance(arbiter.deposit_address, assocBalances => {
			resolve(assocBalances["base"]["stable"]);
		});
	});
}

async function isEligible(arbiter) {
	if (!arbiter.info.pairing_code ||
		!arbiter.info.bio ||
		!arbiter.info.contact_info)
		return false;
	let balance = await getDepositBalance(arbiter.hash);
	if (balance < conf.min_deposit)
		return false;
	return true;
}

exports.create = create;
exports.updateAddress = updateAddress;
exports.getByDeviceAddress = getByDeviceAddress;
exports.getByHash = getByHash;
exports.updateInfo = updateInfo;
exports.getDepositBalance = getDepositBalance;
exports.setEnabled = setEnabled;
exports.isEligible = isEligible;