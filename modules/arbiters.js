/*jslint node: true */
'use strict';
const db = require('ocore/db');
const chash = require('ocore/chash');
const headlessWallet = require('headless-obyte');
const balances = require('ocore/balances');
const conf = require('ocore/conf');
const moment = require('moment');

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

const select_arbiter_sql = `SELECT (fn.value || ' ' || ln.value) AS real_name,
		arbiters.address, 
		arbiters.device_address, 
		arbiters.hash, 
		arbiters.creation_date,
		arbiters.deposit_address, 
		arbiters.enabled, 
		arbiters.visible, 
		arbiters.info, 
		arbiters.announce_unit, 
		cd.name AS device_name,
		MAX(latest_units.creation_date) AS last_unit_date,
		rc.resolved_cnt
	FROM arbiters 

	JOIN correspondent_devices AS cd USING (device_address)

	LEFT JOIN unit_authors AS latest_unit_authors ON arbiters.address=latest_unit_authors.address
	LEFT JOIN units AS latest_units ON latest_units.unit=latest_unit_authors.unit

	LEFT JOIN private_profiles USING(address)
	LEFT JOIN private_profile_fields AS fn ON fn.private_profile_id=private_profiles.private_profile_id AND fn.field='first_name'
	LEFT JOIN private_profile_fields AS ln ON ln.private_profile_id=private_profiles.private_profile_id AND ln.field='last_name'

	LEFT JOIN (SELECT arbiter_address, COUNT(1) AS resolved_cnt, MAX(status_change_date) AS last_resolve_date FROM arbiter_contracts_arbstore WHERE status='resolved' GROUP BY arbiter_address) AS rc ON rc.arbiter_address=arbiters.address
`;

function getByAddress(address) {
	return new Promise(async resolve => {
		let rows = await db.query(select_arbiter_sql + `WHERE arbiters.address=?`, [address]);
		if (rows[0].address)
			return resolve(parseInfo(rows[0]));
		resolve(null);
	});
}

function getByDeviceAddress(device_address) {
	return new Promise(async resolve => {
		let rows = await db.query(select_arbiter_sql + `WHERE device_address=?`, [device_address]);
		if (rows[0].address)
			return resolve(parseInfo(rows[0]));
		resolve(null);
	});
}

function getByHash(hash) {
	return new Promise(async resolve => {
		let rows = await db.query(select_arbiter_sql + `WHERE hash=?`, [hash]);
		if (rows[0].address)
			return resolve(parseInfo(rows[0]));
		resolve(null);
	});
}


function parseInfo(row) {
	row.info = JSON.parse(row.info);
	if (!row.info) row.info = {tags: [], languages: []};
	if (row.last_resolve_date) row.last_resolve_date = moment(row.last_resolve_date).fromNow();
	if (row.creation_date) row.creation_date = moment(row.creation_date).fromNow();
	if (row.last_unit_date) row.last_unit_date = moment(row.last_unit_date).fromNow();
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

function getAllVisible() {
	return new Promise(async resolve => {
		let rows = await db.query(
			`SELECT arbiters.hash,
			(fn.value || ' ' || ln.value) AS real_name,
			arbiters.address,
			arbiters.info,
			arbiters.creation_date,
			tc.total_cnt,
			rc.resolved_cnt,
			rc.last_resolve_date,
			MAX(latest_units.creation_date) AS last_unit_date
			FROM arbiters

			LEFT JOIN (SELECT arbiter_address, COUNT(1) AS total_cnt FROM arbiter_contracts_arbstore GROUP BY arbiter_address) AS tc ON tc.arbiter_address=arbiters.address
			LEFT JOIN (SELECT arbiter_address, COUNT(1) AS resolved_cnt, MAX(status_change_date) AS last_resolve_date FROM arbiter_contracts_arbstore WHERE status='resolved' GROUP BY arbiter_address) AS rc ON rc.arbiter_address=arbiters.address

			JOIN outputs ON outputs.address=arbiters.deposit_address
			JOIN units USING (unit)

			LEFT JOIN unit_authors AS latest_unit_authors ON arbiters.address=latest_unit_authors.address
			LEFT JOIN units AS latest_units ON latest_units.unit=latest_unit_authors.unit

			LEFT JOIN private_profiles USING(address)
			LEFT JOIN private_profile_fields AS fn ON fn.private_profile_id=private_profiles.private_profile_id AND fn.field='first_name'
			LEFT JOIN private_profile_fields AS ln ON ln.private_profile_id=private_profiles.private_profile_id AND ln.field='last_name'
			
			WHERE enabled=1 AND visible=1 AND is_spent=0 AND units.sequence='good' AND units.is_stable=1
			GROUP BY arbiters.deposit_address
			HAVING SUM(amount) >= ?
			`, [conf.min_deposit]);
		rows.forEach(arbiter => {
			arbiter = parseInfo(arbiter);
		});
		resolve(rows);
	});
}

exports.create = create;
exports.updateAddress = updateAddress;
exports.getByAddress = getByAddress;
exports.getByDeviceAddress = getByDeviceAddress;
exports.getByHash = getByHash;
exports.updateInfo = updateInfo;
exports.getDepositBalance = getDepositBalance;
exports.setEnabled = setEnabled;
exports.isEligible = isEligible;
exports.getAllVisible = getAllVisible;