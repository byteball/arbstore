/*jslint node: true */
'use strict';
const db = require('ocore/db');
const chash = require('ocore/chash');
const headlessWallet = require('headless-obyte');
const balances = require('ocore/balances');
const conf = require('ocore/conf');
const moment = require('moment');

async function create(address, device_address){
	let deposit_address = await headlessWallet.issueNextMainAddress();
	let hash = chash.getChash160(address + device_address + deposit_address + Date.now().toString()).substr(0, 16);
	await db.query(`INSERT INTO arbiters (address, device_address, hash, deposit_address) VALUES (?, ?, ?, ?)`, [address, device_address, hash, deposit_address]);
	return [hash, deposit_address];
}

function updateAddress(address, device_address){
	return db.query(`UPDATE arbiters SET address=? WHERE device_address=?`, [address, device_address]);
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
		tc.total_cnt,
		rc.resolved_cnt,
		rc.last_resolve_date,
		rep.reputation,
		MAX(latest_units.creation_date) AS last_unit_date
	FROM arbiters 

	JOIN correspondent_devices AS cd USING (device_address)

	LEFT JOIN unit_authors AS latest_unit_authors ON arbiters.address=latest_unit_authors.address
	LEFT JOIN units AS latest_units ON latest_units.unit=latest_unit_authors.unit

	LEFT JOIN private_profiles USING(address)
	LEFT JOIN private_profile_fields AS fn ON fn.private_profile_id=private_profiles.private_profile_id AND fn.field='first_name'
	LEFT JOIN private_profile_fields AS ln ON ln.private_profile_id=private_profiles.private_profile_id AND ln.field='last_name'

	LEFT JOIN (SELECT arbiter_address, COUNT(1) AS total_cnt FROM arbstore_arbiter_contracts GROUP BY arbiter_address) AS tc ON tc.arbiter_address=arbiters.address
	LEFT JOIN (SELECT arbiter_address, COUNT(1) AS resolved_cnt, MAX(status_change_date) AS last_resolve_date FROM arbstore_arbiter_contracts WHERE status IN ('dispute_resolved', 'appeal_requested', 'in_appeal', 'appeal_declined', 'appeal_approved') GROUP BY arbiter_address) AS rc ON rc.arbiter_address=arbiters.address
	LEFT JOIN arbstore_arbiters_reputation AS rep ON arbiters.address=rep.arbiter_address
`;

async function getByAddress(address) {
	let rows = await db.query(select_arbiter_sql + `WHERE arbiters.address=?`, [address]);
	if (rows[0].address)
		return parseInfo(rows[0]);
	return null;
}

async function getByDeviceAddress(device_address) {
	let rows = await db.query(select_arbiter_sql + `WHERE device_address=?`, [device_address]);
	if (rows[0].address)
		return parseInfo(rows[0]);
	return null;
}

async function getByHash(hash) {
	let rows = await db.query(select_arbiter_sql + `WHERE hash=?`, [hash]);
	if (rows[0].address)
		return parseInfo(rows[0]);
	return null;
}


function parseInfo(row) {
	row.info = JSON.parse(row.info);
	if (!row.info) row.info = {tags: [], languages: []};
	if (row.last_resolve_date) row.last_resolve_date = moment.utc(row.last_resolve_date).fromNow();
	if (row.creation_date) row.creation_date = moment.utc(row.creation_date).fromNow();
	if (row.last_unit_date) row.last_unit_date = moment.utc(row.last_unit_date).fromNow();
	return row;
}

function updateInfo(hash, info, visible){
	return db.query(`UPDATE arbiters SET info=?, visible=? WHERE hash=?`, [JSON.stringify(info), visible, hash]);
}

function setEnabled(hash, enabled) {
	return db.query(`UPDATE arbiters SET enabled=? WHERE hash=?`, [!!enabled, hash]);
}

function getDepositBalance(hash) {
	return new Promise(async resolve => {
		let arbiter = await getByHash(hash);
		balances.readOutputsBalance(arbiter.deposit_address, assocBalances => {
			if (assocBalances[conf.asset || "base"])
				resolve(assocBalances[conf.asset || "base"]["total"]);
			else
				resolve(0);
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

async function getAllVisible() {
	let rows = await db.query(
		`SELECT arbiters.hash,
		(fn.value || ' ' || ln.value) AS real_name,
		arbiters.address,
		arbiters.info,
		arbiters.creation_date,
		tc.total_cnt,
		rc.resolved_cnt,
		rc.last_resolve_date,
		rep.reputation,
		MAX(latest_units.creation_date) AS last_unit_date,
			(SELECT IFNULL(SUM(amount), 0) FROM outputs 
			JOIN units USING(unit) 
			WHERE outputs.address=arbiters.deposit_address AND is_spent=0 AND sequence='good' AND is_stable=1 AND outputs.asset IS ?) AS balance
		FROM arbiters

		LEFT JOIN (SELECT arbiter_address, COUNT(1) AS total_cnt FROM arbstore_arbiter_contracts GROUP BY arbiter_address) AS tc ON tc.arbiter_address=arbiters.address
		LEFT JOIN (SELECT arbiter_address, COUNT(1) AS resolved_cnt, MAX(status_change_date) AS last_resolve_date FROM arbstore_arbiter_contracts WHERE status IN ('dispute_resolved', 'appeal_requested', 'in_appeal', 'appeal_declined', 'appeal_approved') GROUP BY arbiter_address) AS rc ON rc.arbiter_address=arbiters.address

		LEFT JOIN unit_authors AS latest_unit_authors ON arbiters.address=latest_unit_authors.address
		LEFT JOIN units AS latest_units ON latest_units.unit=latest_unit_authors.unit

		LEFT JOIN private_profiles USING(address)
		LEFT JOIN private_profile_fields AS fn ON fn.private_profile_id=private_profiles.private_profile_id AND fn.field='first_name'
		LEFT JOIN private_profile_fields AS ln ON ln.private_profile_id=private_profiles.private_profile_id AND ln.field='last_name'

		LEFT JOIN arbstore_arbiters_reputation AS rep ON arbiters.address=rep.arbiter_address
		
		WHERE enabled=1 AND visible=1 AND balance >= ?
		GROUP BY arbiters.deposit_address
		ORDER BY reputation DESC, resolved_cnt DESC, total_cnt DESC, last_resolve_date DESC, real_name DESC
		`, [conf.asset, conf.min_deposit]);
	rows.forEach(arbiter => {
		arbiter = parseInfo(arbiter);
	});
	return rows;
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