/*jslint node: true */
'use strict';
const _ = require('lodash');
const crypto = require('crypto');
const conf = require('ocore/conf');
const db = require('ocore/db');
const eventBus = require('ocore/event_bus.js');
const texts = require('./modules/texts.js');
const validationUtils = require('ocore/validation_utils');
const fs = require('fs');
const arbiters = require('./modules/arbiters.js');
const contracts = require('./modules/contracts.js');
const device = require('ocore/device.js');
const privateProfile = require('ocore/private_profile.js');
const headlessWallet = require('headless-obyte');
const network = require('ocore/network.js');
const storage = require('ocore/storage.js');
const objectHash = require('ocore/object_hash.js');
const balances = require('ocore/balances.js');
const wallet = require('ocore/wallet.js');
const constants = require('ocore/constants.js');

const Koa = require('koa');
const app = new Koa();
const views = require('koa-views');
const KoaRouter = require('koa-router');
const bodyParser = require('koa-bodyparser');
const multer = require('@koa/multer');
const serve = require('koa-static');
const router = new KoaRouter();
const cors = require('@koa/cors');
const mount = require('koa-mount');
const moderatorRouter = new KoaRouter({prefix: '/moderator'});
const apiRouter = new KoaRouter();
const walletApiRouter = new KoaRouter({prefix: '/api'});
const sharp = require('sharp');

app.use(mount('/assets/', serve(__dirname + '/assets')));
const upload = multer();
app.use(cors());


let available_languages = {};
fs.readFile('languages.json', 'utf8', function(err, contents) {
	available_languages = JSON.parse(contents);
});

let last_plaintiff_device_address = null;
let appellant_device_address = null;
let arbstoreFirstAddress = null;

function onReady() {
	headlessWallet.readFirstAddress(async address => {
		arbstoreFirstAddress = address;
	});
	eventBus.on('paired', (from_address, secret) => {
		lastSecret = secret;
		lastPairedAddress = from_address;
		if (last_plaintiff_device_address === from_address || appellant_device_address === from_address) {
			last_plaintiff_device_address = null;
			appellant_device_address = null;
			return;
		}
		device.sendMessageToDevice(from_address, 'text', texts.greetings());
	});

	async function getProfileHash(address) {
		if (conf.bLight){
			const light_attestations = require('./modules/light_attestations.js');
			await light_attestations.updateAttestationsInLight(address);
		}
		return new Promise(resolve => {
			db.query(
				`SELECT value FROM attested_fields WHERE address=? AND field='profile_hash' AND attestor_address IN (?)`, [address, conf.trustedAttestorAddresses], resolve);
		});
	}

	eventBus.on('text', (from_address, text) => {
		let respond = (text) => {
			device.sendMessageToDevice(from_address, 'text', text);
		};
		let parser = (input, rules) => {
			for (let i = 0; i < rules.length; i++) {
				let rule = rules[i];
				if (rule.function) {
					let match = rule.function(input);
					if (match) {
						rule.action(match);
						return;
					}
					continue;
				}
				let found = input.match(rule.pattern);
				if (found) {
					rule.action(found);
					return;
				}
				
			}
		};
		parser(text.trim(), [
			{function: validationUtils.isValidAddress, action: async () => {
				let address = text.trim();
				let rows = await getProfileHash(address);
				if (!rows.length)
					return respond(texts.not_attested());
				respond(`Now we need to confirm that you are the owner of address ${address}. Please sign the following message: [s](sign-message-request:${texts.signMessage(address)})`);
			}},
			{pattern: /\(signed-message:(.+?)\)/, action: async (arrSignedMessageMatches) => {
				let current_arbiter = await arbiters.getByDeviceAddress(from_address);
				if (current_arbiter && current_arbiter.announce_unit)
					return respond(texts.already_announced());
				let signedMessageBase64 = arrSignedMessageMatches[1];
				var validation = require('ocore/validation.js');
				var signedMessageJson = Buffer(signedMessageBase64, 'base64').toString('utf8');
				try{
					var objSignedMessage = JSON.parse(signedMessageJson);
				}
				catch(e){
					return null;
				}
				validation.validateSignedMessage(objSignedMessage, async err => {
					if (err)
						return respond(texts.wrong_signature());
					let address = objSignedMessage.authors[0].address;
					if (objSignedMessage.signed_message != texts.signMessage(address))
						return respond(`wrong message text signed`);
					let rows = await getProfileHash(address);
					if (!rows.length)
						return respond(texts.not_attested());
					db.query(`SELECT DISTINCT address FROM attested_fields JOIN arbiters USING(address) WHERE field='profile_hash' AND value=? AND arbiters.address!=?`, [rows[0], address], async (rows) => {
						if (rows.length > 0)
							return respond(texts.already_registered_from_different_address());
						if (current_arbiter) {
							arbiters.updateAddress(address, from_address);							
						} else {
							arbiters.create(address, from_address);
						}
						return respond(texts.reveal_profile());
					});
				});
			}},
			{pattern: /\(profile:(.+?)\)|stay anonymous/, action: async (arrProfileMatches) => {
				let current_arbiter = await arbiters.getByDeviceAddress(from_address);
				if (!current_arbiter)
					return respond(texts.device_address_unknown());
				if (arrProfileMatches[1]) {
					let privateProfileJsonBase64 = arrProfileMatches[1];
					let objPrivateProfile = privateProfile.getPrivateProfileFromJsonBase64(privateProfileJsonBase64);
					if (!objPrivateProfile)
						return respond('Invalid private profile');
					privateProfile.parseAndValidatePrivateProfile(objPrivateProfile, (err, address, attestor_address) => {
						if (err)
							return respond(`Failed to parse the private profile: ${err}`);
						if (current_arbiter.address !== address)
							return respond(`Submitted profile is for different address, please send the profile for address ${current_arbiter.address}`);
						let assocPrivateData = privateProfile.parseSrcProfile(objPrivateProfile.src_profile);
						let arrMissingFields = _.difference(['first_name', 'last_name'], Object.keys(assocPrivateData));
						if (arrMissingFields.length > 0)
							return respond(`These fields are missing in your profile: ${arrMissingFields.join(', ')}`);
						privateProfile.savePrivateProfile(objPrivateProfile, address, attestor_address);
						respond(`Profile of ${assocPrivateData.first_name} ${assocPrivateData.last_name} saved`);
					});
				}
				let token = respond(`Now complete your arbiter profile here: ${conf.ArbStoreWebURI}${encryptWebToken(current_arbiter.hash)}`);
			}},
			{pattern: /^([\w\/+]+)@([\w.:\/-]+)#(.+)$/, action: async matches => { // pairing code
				let current_arbiter = await arbiters.getByDeviceAddress(from_address);
				if (!current_arbiter)
					return respond(texts.device_address_unknown());
				var pubkey = matches[1];
				var hub = matches[2];
				var pairing_secret = matches[3];
				if (pubkey.length !== 44)
					return respond(`Invalid pubkey length`);
				Object.assign(current_arbiter.info, {pairing_code: matches[0]});
				arbiters.updateInfo(current_arbiter.hash, current_arbiter.info, current_arbiter.visible);
				postAnnounceUnit(current_arbiter.hash);
			}},
			{pattern: /^help$/, action: () => respond(texts.help())},
			{pattern: /^status$/, action: async () => {
				let current_arbiter = await arbiters.getByDeviceAddress(from_address);
				if (!current_arbiter)
					respond(texts.greetings());
				else {
					current_arbiter.balance = await arbiters.getDepositBalance(current_arbiter.hash);
					respond(texts.current_status(current_arbiter));
				}
			}},
			{pattern: /^edit\sinfo$/, action: async () => {
				let current_arbiter = await arbiters.getByDeviceAddress(from_address);
				if (!current_arbiter)
					return respond(texts.device_address_unknown());
				respond(`Edit your arbiter profile here: ${conf.ArbStoreWebURI}${encryptWebToken(current_arbiter.hash)}`)
			}},
			{pattern: /^suspend$/, action: async () => {
				let current_arbiter = await arbiters.getByDeviceAddress(from_address);
				if (!current_arbiter)
					return respond(texts.device_address_unknown());
				arbiters.updateInfo(current_arbiter.hash, current_arbiter.info, false);
				respond(`Your listing suspended`);
			}},
			{pattern: /^live$/, action: async () => {
				let current_arbiter = await arbiters.getByDeviceAddress(from_address);
				if (!current_arbiter)
					return respond(texts.device_address_unknown());
				arbiters.updateInfo(current_arbiter.hash, current_arbiter.info, true);
				respond(`You are visible again now`);
			}},
			{pattern: /^revive$/, action: async () => {
				let current_arbiter = await arbiters.getByDeviceAddress(from_address);
				if (!current_arbiter)
					return respond(texts.device_address_unknown());
				postAnnounceUnit(current_arbiter.hash);
			}},
			{pattern: /^withdraw\s?(all)?$/, action: async matches => {
				let all = (matches[1] === "all");
				if (network.isCatchingUp())
					return respond(`Sync is in progress, try again later`);
				let current_arbiter = await arbiters.getByDeviceAddress(from_address);
				if (!current_arbiter)
					return respond(texts.device_address_unknown());
				try {
					let amount = await arbiters.getDepositBalance(current_arbiter.hash);
					if (!all)
						amount -= conf.min_deposit;
					if (amount <= 0)
						return respond(texts.not_enough_funds(amount+conf.min_deposit));
					let res = await headlessWallet.sendMultiPayment({
						paying_addresses: [current_arbiter.deposit_address],
						change_address: current_arbiter.deposit_address,
						to_address: current_arbiter.address,
						fee_paying_wallet: [arbstoreFirstAddress],
						recipient_device_address: from_address,
						asset: conf.asset || "base",
						amount: amount
					});
					respond(texts.withdraw_completed(amount, res.unit, current_arbiter.address));
				} catch(e) {
					respond(`${e}`);
				}
			}},
			{function: input => input.split(/\r\n|\r|\n/).length < 2 ? false : input.split(/\r\n|\r|\n/), action: async lines => { // service fee, or any multiline message
				let current_arbiter = await arbiters.getByDeviceAddress(from_address);
				if (!current_arbiter)
					return respond(texts.device_address_unknown());
				if (!(/^\d+\.?\d*$/.test(lines[1])) || !(parseFloat(lines[1]) > 0))
					return respond(`incorrect amount`);
				let amount = parseFloat(lines[1]);
				if (!conf.asset || conf.asset === "base" || conf.asset === constants.BLACKBYTES_ASSET)
					amount *= Math.pow(10, 9);
				amount *= Math.pow(10, (texts.assetMetadata ? texts.assetMetadata.decimals : 0));
				let hash = lines[0];
				let contract = await contracts.get(hash);
				if (!contract)
					return respond(`incorrect contract hash`);
				if (contract.status !== 'dispute_requested')
					return respond(`contract is not in dispute`);
				let comment = lines.length > 2 ? lines[2].replace(/(.*)\[.*\]\(.*\)(.*)/g, "$1$2") : "";
				// pair with plaintiff and send payment request
				let matches = contract.plaintiff_pairing_code.match(/^([\w\/+]+)@([\w.:\/-]+)#(.+)$/);
				if (!matches)
					return respond(`Invalid pairing code`);
				var pubkey = matches[1];
				var hub = matches[2];
				var pairing_secret = matches[3];
				if (pubkey.length !== 44)
					return respond(`Invalid pubkey length`);
				await contracts.updateField("service_fee", hash, amount);
				device.addUnconfirmedCorrespondent(pubkey, hub, 'New', function(device_address){
					last_plaintiff_device_address = device_address;
					device.startWaitingForPairing(function(reversePairingInfo){
						device.sendPairingMessage(hub, pubkey, pairing_secret, reversePairingInfo.pairing_secret, {
							ifOk: () => {
								headlessWallet.issueNextMainAddress(async address => {
									await contracts.updateField("service_fee_address", contract.hash, address);
									device.sendMessageToDevice(device_address, 'text', texts.payForArbiterService(current_arbiter.real_name, amount, address, current_arbiter.info.pairing_code, comment));
								});
							},
							ifError: respond
						});
					});
				});

				respond(texts.serviceFeeSet(hash, amount));
			}},
			{pattern: /.*/, action: () => {
				respond(texts.unrecognized_command());
			}}
		]);
	});
	
	// send accumulated service fees to arbiters
	setInterval(async () => {
		let rows = await db.query(`SELECT wac.hash, arbiters.deposit_address, wac.arbiter_address, wac.service_fee_address FROM arbstore_arbiter_contracts AS wac
			JOIN arbiters ON arbiters.address=wac.arbiter_address
			WHERE wac.status IN ('dispute_resolved', 'appeal_approved', 'appeal_declined')
			AND julianday('now') - julianday(wac.status_change_date) > -1`, []);
		rows.forEach(row => {
			balances.readOutputsBalance(row.service_fee_address, async (assocBalances) => {
				if (!assocBalances[conf.asset || "base"] || assocBalances[conf.asset || "base"].total == 0)
					return;
				try {
					let amount = Math.round((1-conf.ArbStoreCut) * assocBalances[conf.asset || "base"].total);
					let res = await headlessWallet.sendMultiPayment({
						paying_addresses: [row.service_fee_address],
						change_address: row.service_fee_address,
						fee_paying_wallet: [arbstoreFirstAddress],
						to_address: row.deposit_address,
						asset: conf.asset || "base",
						amount: amount
					});
					let arbiter = await arbiters.getByAddress(row.arbiter_address);
					device.sendMessageToDevice(arbiter.device_address, "text", texts.service_fee_sent(row.hash, amount, conf.ArbStoreCut, res.unit));

					// send ArbStoreCut to our first address
					await headlessWallet.sendMultiPayment({
						paying_addresses: [row.service_fee_address],
						change_address: row.service_fee_address,
						fee_paying_wallet: [arbstoreFirstAddress],
						to_address: arbstoreFirstAddress,
						asset: conf.asset || "base",
						amount: assocBalances[conf.asset || "base"].total - amount
					});
				} catch (e) {
					console.warn('error while trying to send payment to arbiter from address '+row.service_fee_address+', balance: ' + assocBalances[conf.asset || "base"].total)
					return;
				}
			});
		});
	}, 3*1000);

	// read asset metadata
	if (conf.asset && conf.asset !== constants.BLACKBYTES_ASSET) {
		wallet.readAssetMetadata([conf.asset], (metadata) => {
			texts.assetMetadata = metadata[conf.asset];
		});
	}
};

async function checkDeposit(hash) {
	let arbiter = await arbiters.getByHash(hash);
	let balance = await arbiters.getDepositBalance(hash);
	if (balance < conf.min_deposit) {
		device.sendMessageToDevice(arbiter.device_address, 'text', texts.topup_deposit(conf.min_deposit-balance, arbiter.deposit_address));
	}
	else {
		checkPairingCode(hash);
	}
}

async function checkPairingCode(hash) {
	let arbiter = await arbiters.getByHash(hash);
	if (arbiter.info.pairing_code)
		return postAnnounceUnit(hash);
	return device.sendMessageToDevice(arbiter.device_address, 'text', texts.request_pairing_code());
}

async function postAnnounceUnit(hash) {
	let arbiter = await arbiters.getByHash(hash);
	let balance = await arbiters.getDepositBalance(hash);
	if (balance < conf.min_deposit)
		return checkDeposit(hash);

	let onError = (err) => {
		device.sendMessageToDevice(arbiter.device_address, 'text', `Error: ${err}`);
	};
	
	if (arbiter.announce_unit) {
		let rows = await db.query(`SELECT julianday('now') - julianday(creation_date) AS date_diff FROM units WHERE unit=?`, [arbiter.announce_unit]);
		if (rows[0].date_diff < 1)
			return onError(`You can only announce yourself once per day`);
	}

	const composer = require('ocore/composer.js');
	const objectHash = require('ocore/object_hash.js');

	let payload = {
		address: arbiter.address
	};
	let objMessage = {
		app: "data",
		payload_location: "inline",
		payload_hash: objectHash.getBase64Hash(payload),
		payload: payload
	};
	try {
		let res = await headlessWallet.sendMultiPayment({
			paying_addresses: [arbstoreFirstAddress],
			messages: [objMessage],
			change_address: arbstoreFirstAddress
		});
		db.query(`UPDATE arbiters SET announce_unit=? WHERE hash=?`, [res.unit, arbiter.hash]);
		device.sendMessageToDevice(arbiter.device_address, 'text', texts.unit_posted(res.unit));
	} catch(e) {
		onError(`${e}`);
	}
}

// deposit topup
eventBus.on('new_my_transactions', async arrUnits => {
	let rows = await db.query(
		`SELECT SUM(outputs.amount) as amount, hash
		FROM outputs
		CROSS JOIN arbiters ON outputs.address=arbiters.deposit_address
		JOIN unit_authors ON outputs.unit=unit_authors.unit AND unit_authors.address=arbiters.address -- only payments from arbiter address
		WHERE outputs.unit IN(?) AND outputs.asset IS ?
		GROUP BY deposit_address`, [arrUnits, conf.asset]);
	rows.forEach(async row => {
		let amount = row.amount;
		let arbiter = await arbiters.getByHash(row.hash);
		device.sendMessageToDevice(arbiter.device_address, 'text', texts.received_payment(amount));
	});
});

// deposit topup became stable
eventBus.on('my_transactions_became_stable', async arrUnits => {
	let rows = await db.query(
		`SELECT hash
		FROM outputs
		CROSS JOIN arbiters ON outputs.address=arbiters.deposit_address
		JOIN unit_authors ON outputs.unit=unit_authors.unit AND unit_authors.address=arbiters.address -- only payments from arbiter address
		WHERE outputs.unit IN(?) AND outputs.asset IS ?
		GROUP BY deposit_address`, [arrUnits, conf.asset]);
	rows.forEach(async row => {
		let arbiter = await arbiters.getByHash(row.hash);
	 	device.sendMessageToDevice(arbiter.device_address, 'text', texts.payment_confirmed());
		checkDeposit(row.hash);
	});
});

// service fee paid
let serviceFeePaymentHandler = async (arrUnits, type) => {
	let rows = await db.query(
		`SELECT hash, SUM(outputs.amount) AS amount
		FROM outputs
		CROSS JOIN arbstore_arbiter_contracts AS arb_c ON outputs.address=arb_c.service_fee_address
		WHERE outputs.unit IN(?) AND outputs.asset IS ?
		GROUP BY service_fee_address`, [arrUnits, conf.asset]);
	rows.forEach(async row => {
		let contract = await contracts.get(row.hash);
		if (contract.status !== "dispute_requested" || row.amount < contract.service_fee) return;
		let arbiter = await arbiters.getByAddress(contract.arbiter_address);
		let plaintiff_device_address = objectHash.getDeviceAddress(contract.plaintiff_pairing_code.split('@')[0]);
		if (type === 'stable') {
			await contracts.updateStatus(contract.hash, "in_dispute");
		 	device.sendMessageToDevice(arbiter.device_address, 'text', texts.service_fee_paid(contract.hash, row.amount));
		 	device.sendMessageToDevice(plaintiff_device_address, 'text', texts.service_fee_stabilized());
		} else {
			device.sendMessageToDevice(plaintiff_device_address, 'text', texts.service_fee_paid_plaintiff(contract.hash, row.amount));
		}
	});
};
eventBus.on('new_my_transactions', arrUnits => {serviceFeePaymentHandler(arrUnits, 'new')});
eventBus.on('my_transactions_became_stable', arrUnits => {serviceFeePaymentHandler(arrUnits, 'stable')});

// appeal fee paid
eventBus.on('my_transactions_became_stable', async arrUnits => {
	let rows = await db.query(
		`SELECT hash, SUM(outputs.amount) AS amount
		FROM outputs
		CROSS JOIN arbstore_arbiter_contracts AS arb_c ON outputs.address=arb_c.appeal_fee_address
		WHERE outputs.unit IN(?) AND outputs.asset IS ?
		GROUP BY appeal_fee_address`, [arrUnits, conf.asset]);
	rows.forEach(async row => {
		let contract = await contracts.get(row.hash);
		if (contract.status !== "appeal_requested" || row.amount < conf.AppealFeeAmount) return;
		await contracts.updateStatus(contract.hash, "in_appeal");
		let pdRows = await db.query(
			`SELECT device_address
			FROM correspondent_devices
			WHERE device_address IN (?)`, [conf.ModeratorDeviceAddresses]
		);
		pdRows.forEach(pdRow => {
			device.sendMessageToDevice(pdRow.device_address, 'text', texts.appeal_fee_paid(contract.hash, contract.contract.title));
		})
		let appellant_device_address;
		if (contract.plaintiff_side !== contract.winner_side) {
			appellant_device_address = objectHash.getDeviceAddress(contract.plaintiff_pairing_code.split('@')[0]);
		} else {
			appellant_device_address = objectHash.getDeviceAddress(contract.peer_pairing_code.split('@')[0]);
		}
		device.sendMessageToDevice(appellant_device_address, 'text', texts.appeal_fee_paid_appellant(contract.hash, contract.contract.title));
	});
});

// snipe for arbiter contracts and calculate statistics
function extractContractFromUnit(unit) {
	return new Promise(async (resolve, reject) => {
		let rows = await db.query(
			`SELECT unit, payload, unit_authors.address AS shared_address, definition
			FROM messages
			JOIN unit_authors USING(unit)
			JOIN definitions USING(definition_chash)
			WHERE unit=? AND payload LIKE '{"contract_text_hash"%"arbiter"%' AND definition LIKE '["or",%'`, [unit]);
		rows.forEach(async row => {
			let contract_hash = row.payload.match(/"contract_text_hash":"([^"]+)"/);
			if (!contract_hash)
				return reject("no contract hash in the unit");
			let arbiter_address = row.payload.match(/"arbiter":"([^"]+)"/);
			if (!arbiter_address)
				return reject("no arbiter_address in the unit");
			let arbiter = await arbiters.getByAddress(arbiter_address[1]);
			if (!arbiter)
				return reject("arbiter is now known to this arbstore");
			let definitionObj = JSON.parse(row.definition);
			let side1_address = _.get(definitionObj, '[1][0][1][0][1]');
			let side2_address = _.get(definitionObj, '[1][0][1][1][1]');
			if (!side1_address || !side2_address)
				return reject("can't find side addresses in the unit");
			let asset = row.definition.match(/"asset":"([^"]+)"/);
			let amount = _.get(definitionObj, '[1][1][1][1][1].amount');
			if (!asset && !amount) { // probably private asset
			} else { // public asset
				if (!asset)
					return reject("no asset in the unit");
				if (!amount || !validationUtils.isPositiveInteger(amount))
					return reject("no amount in the unit");
			}
			if (asset && asset[1] === "base")
				asset[1] = null;
			await contracts.insertNew(contract_hash[1], row.unit, row.shared_address, arbiter, amount, asset ? asset[1] : null, 'active', side1_address, side2_address);
			resolve(await contracts.get(contract_hash[1]));
		});
		if (rows.length === 0) {
			return reject("unit either not known to arbstore yet or does not contain any contract info");
		}
	});
}
eventBus.on('saved_unit', objJoint => {
	extractContractFromUnit(objJoint.unit.unit).catch(e => {});
});


// snipe for arbiter dispute response and calculate statistics
eventBus.on('mci_became_stable', async mci => {
	let rows = await db.query(
		`SELECT unit, address
		FROM units
		JOIN unit_authors USING(unit)
		JOIN arbiters USING(address)
		WHERE main_chain_index=?`, [mci]);
	rows.forEach(async row => {
		let unit = await storage.readUnit(row.unit);
		unit.messages.forEach(async m => {
			if (m.app !== "data_feed")
				return;
			for (let key in m.payload) {
				let contract_hash_matches = key.match(/CONTRACT_(.+)/);
				if (!contract_hash_matches)
					continue;
				let contract_hash = contract_hash_matches[1];
				let contract = await contracts.get(contract_hash);
				if (!contract)
					continue;
				if (contract.status === 'in_dispute' || contract.status === 'dispute_requested') {
					await contracts.updateStatus(contract_hash, 'dispute_resolved');
				}
				let winner_address = m.payload[key];
				await contracts.updateField("winner_side", contract_hash, winner_address == contract.side1_address ? 1 : 2);
			}
		});
	});
});

// contract was completed 
eventBus.on('mci_became_stable', async mci => {
	let rows = await db.query(
		`SELECT DISTINCT hash, arbiter_address
		FROM units
		JOIN inputs USING(unit)
		CROSS JOIN arbstore_arbiter_contracts AS arb_c ON inputs.address=arb_c.shared_address
		WHERE arb_c.status='in_dispute' AND main_chain_index=? `, [mci]);
	rows.forEach(async row => {
		let contract = await contracts.get(row.hash);
		await contracts.updateStatus(contract.hash, "completed");
		let arbiter = await arbiters.getByAddress(row.arbiter_address);
		device.sendMessageToDevice(arbiter.device_address, 'text', texts.contract_completed(row.hash));
	});
});

// arbiter appeal stats
eventBus.on('mci_became_stable', async mci => {
	let rows = await db.query(
		`SELECT payload
		FROM messages
		JOIN unit_authors USING(unit)
		JOIN units USING(unit)
		WHERE main_chain_index=? AND payload IS NOT NULL AND address IN (?)`, [mci, conf.ArbStoreAddresses.concat([arbstoreFirstAddress])]);
	rows.forEach(async row => {
		const data = JSON.parse(row.payload);
		if (data.appealed != true || !data.arbiter_address)
			return;
		let arRows = await db.query(`SELECT reputation FROM arbstore_arbiters_reputation WHERE arbiter_address=?`, [data.arbiter_address]);
		if (arRows.length)
			await db.query(`UPDATE arbstore_arbiters_reputation SET reputation = reputation-1 WHERE arbiter_address=?`, [data.arbiter_address]);
		else
			await db.query(`INSERT INTO arbstore_arbiters_reputation (arbiter_address, reputation) VALUES (?, ?)`, [data.arbiter_address, -1]);
	});
});

function encrypt(text){
	let cipher = crypto.createCipher('aes-256-ctr', conf.WebTokenSalt);
	let crypted = cipher.update(text, 'utf8', 'hex');
	crypted += cipher.final('hex');
	return crypted;
}

function decrypt(text){
	let decipher = crypto.createDecipher('aes-256-ctr', conf.WebTokenSalt);
	try {
		let dec = decipher.update(text, 'hex', 'utf8');
		dec += decipher.final('utf8');
		return dec;
	} catch (e) {
		return "";
	}
}

function encryptWebToken(arbiter_hash){
	return encrypt(`${arbiter_hash}:${Math.floor(Date.now() / 1000 / 60 / 60)}`);
}

function decryptWebToken(token){
	let hash_hours = decrypt(token);
	let [hash, hours] = hash_hours.split(':');
	if (!hash || !hours)
		return null;
	let current_hours = Math.floor(Date.now() / 1000 / 60 / 60);
	if (current_hours - hours > 1)
		return null;
	return hash;
}

app.use(views(__dirname + '/views', {
	map: {
		html: 'ejs'
	}
}));
app.use(bodyParser());

// ArbStore Web routes
router.get('/', async ctx => {
	let arbiter_list = await arbiters.getAllVisible();
	const protocol = process.env.devnet ? 'obyte-dev:' : (process.env.testnet ? 'obyte-tn:' : 'obyte:');
	const pairing_link = protocol + device.getMyDevicePubKey() + "@" + conf.hub + "#" + conf.permanent_pairing_secret;
	if (ctx.useJSON){
		let arbiters = [];
		arbiter_list.forEach(a => {
			const {balance: _skip1, ...cleanArbiter} = a;
			const {pairing_code: _skip2, ...cleanInfo} = a.info;
			cleanArbiter.info = cleanInfo;
			arbiters.push(cleanArbiter);
		});
		ctx.body =  arbiters;
	} else {
		await ctx.render('index', { arbiter_list: arbiter_list, pairing_link });
	}
});
router.get('/thankyou.html', async ctx => {
	await ctx.render('thankyou');
});
router.get('/userguide', async ctx => {
	await ctx.render('userguide');
});
router.get('/arbiterguide', async ctx => {
	await ctx.render('arbiterguide');
});
router.get('/arbiter/:hash', async ctx => {
	let hash = ctx.params['hash'];
	if (!hash)
		ctx.throw(404);
	let arbiter;
	if (hash.length === 16)
		arbiter = await arbiters.getByHash(hash);
	else 
		arbiter = await arbiters.getByAddress(hash);
	if (!arbiter)
		ctx.throw(404, `hash not found`);
	
	if (ctx.useJSON){
		ctx.body = _.pick(arbiter, [
			'hash',
			'real_name',
			'device_name',
			'address',
			'creation_date',
			'last_unit_date',
			'last_resolve_date',
			'visible',
			'total_cnt',
			'resolved_cnt',
			'reputation',
			'info'
		]);
		const { pairing_code: _skip, ...cleanInfo} = ctx.body.info;
		ctx.body.info = cleanInfo;
	}
	else {
		arbiter.available_languages = available_languages;
		await ctx.render('arbiter', arbiter);
	}
});
router.get('/:token', async ctx => {
	let token = ctx.params['token'];
	if (!token)
		ctx.throw(404);
	let hash = decryptWebToken(token) || ctx.cookies.get('hash');
	if (!hash)
		ctx.throw(404, `invalid token`);
	let arbiter = await arbiters.getByHash(hash);
	if (!arbiter)
		ctx.throw(404, `hash not found`);
	
	ctx.cookies.set('hash', arbiter.hash);

	arbiter.error = ctx.query.error;
	arbiter.success = ctx.query.success;
	if (ctx.useJSON){
		ctx.body = arbiter;
	}
	else {
		arbiter.available_tags = conf.available_tags;
		arbiter.available_languages = available_languages;
		await ctx.render('edit_arbiter', arbiter);
	}
});
router.post('/:token', upload.single('photo'), async ctx => {
	let token = ctx.params['token'];
	if (!token)
		ctx.throw(404);
	let hash = decryptWebToken(token) || ctx.cookies.get('hash');
	if (!hash)
		ctx.throw(404, `invalid token`);
	let error;
	let is_new_arbiter = true;
	try {
		console.log(ctx.request.body);
		let body = ctx.request.body;
		if (!body.bio)
			throw(`Bio is missing`);

		let tags = {};
		for (let key in body) {
			let value = body[key];
			let matches = key.match(/^tag-(\d)$/);
			let idx = matches ? matches[1] : null;
			if (idx && value === "on") {
				let price_tag = body[`price-tag-${idx}`];
				if (!price_tag)
					throw(`no price for specialization: ${conf.available_tags[idx|0]}`);
				tags[conf.available_tags[idx|0]] = price_tag;
			}
		}
		if (Object.keys(tags).length === 0)
			throw(`Pick at least one specialization`);

		let languages = [];
		if (!Array.isArray(body.languages))
			body.languages = [];
		body.languages.forEach(l => {
			if (available_languages[l])
				languages.push(l);
		});
		if (languages.length === 0)
			throw(`Pick at least one language`);

		let current_arbiter = await arbiters.getByHash(hash);

		// resize photo
		if (ctx.request.file) {
			const dir = 'assets/uploads';
			if (!fs.existsSync(dir)){
				fs.mkdirSync(dir);
			}
			sharp(ctx.request.file.buffer).resize(200, 200).jpeg({ mozjpeg: true }).toFile(`${dir}/${current_arbiter.hash}.jpeg`);
		}

		const info = {
			"short_bio": body.short_bio,
			"bio": body.bio,
			"contact_info": body.contact_info,
			"tags": tags,
			"languages": languages
		}
		
		if (current_arbiter.info.bio)
			is_new_arbiter = false; // just updating info, skjp following steps

		Object.assign(current_arbiter.info, info);
		arbiters.updateInfo(current_arbiter.hash, current_arbiter.info, !!body.visible);
	} catch (e) {
		error = e;
	} finally {
		if (!error && is_new_arbiter) {
			checkDeposit(hash);
			return ctx.redirect(`/thankyou.html`);
		}
		ctx.redirect(`${ctx.path}?${error ? 'error=' + error : 'success=true'}`);
	}
});

// ArbStore Moderator Web routes
let lastPairedAddress = '';
let lastSecret = '';
moderatorRouter.get('/checklogin', async ctx => {
	if (!conf.ModeratorDeviceAddresses.includes(lastPairedAddress) || decodeURIComponent(ctx.query['secret']) !== lastSecret)
		return ctx.body='false';
	ctx.cookies.set('address', encrypt(lastPairedAddress));
	ctx.redirect('/moderator');
});
moderatorRouter.get('/pair', async ctx => {
	async function waitForPairing() {
		return new Promise(resolve => device.startWaitingForPairing(resolve));
	};
	let pi = await waitForPairing();
	await ctx.render('login', {pairing_code: `${process.env.testnet ? 'obyte-tn' : 'obyte'}:${pi.device_pubkey}@${pi.hub}#${pi.pairing_secret}`, secret: pi.pairing_secret});
});
function checkLogin(ctx) {
	let address = decrypt(ctx.cookies.get('address'));
	if (!address || !conf.ModeratorDeviceAddresses.includes(address))
		ctx.redirect('/moderator/pair');
};
moderatorRouter.get('/', async ctx => {
	checkLogin(ctx);
	let in_appeal = await contracts.getAllByStatus(['in_appeal']);
	let closed = await contracts.getAllByStatus(['appeal_declined', 'appeal_approved']);
	await ctx.render('moderator', {in_appeal: in_appeal, closed: closed});
});
moderatorRouter.get('/:hash', async ctx => {
	checkLogin(ctx);
	let hash = ctx.params['hash'];
	if (!hash)
		ctx.throw(404, 'no contract hash');
	hash = decodeURIComponent(hash);
	let contract = await contracts.get(hash);
	if (!contract)
		ctx.throw(404, `hash not found`);
	contract.arbiter = await arbiters.getByAddress(contract.arbiter_address);
	await ctx.render('moderator_contract', contract);
});
moderatorRouter.post('/:hash', async ctx => {
	checkLogin(ctx);
	let hash = ctx.params['hash'];
	if (!hash)
		ctx.throw(404, 'no contract hash');
	hash = decodeURIComponent(hash);
	let contract = await contracts.get(hash);
	if (!contract)
		ctx.throw(404, `hash not found`);
	if (contract.status !== 'in_appeal')
		ctx.throw(404, `contract is not in appeal process`);
	let arbiter = await arbiters.getByAddress(contract.arbiter_address);

	let action = ctx.query['action'];
	if (!action)
		ctx.throw(404, `action not found`);
	
	let appellant_device_address;
	if (contract.plaintiff_side != contract.winner_side) {
		appellant_device_address = objectHash.getDeviceAddress(contract.plaintiff_pairing_code.split('@')[0]);
	} else {
		appellant_device_address = objectHash.getDeviceAddress(contract.peer_pairing_code.split('@')[0]);
	}

	if (action === 'approve') {
		let loser = contract.winner_side === 1 ? contract.side2_address : contract.side1_address;
		try {
			let res = await headlessWallet.sendMultiPayment({
				paying_addresses: [arbiter.deposit_address],
				fee_paying_wallet: [arbstoreFirstAddress],
				to_address: loser,
				amount: 3*conf.AppealFeeAmount,
				asset: conf.asset,
				change_address: arbiter.deposit_address,
				recipient_device_address: appellant_device_address
			});
			// decrease arbiter reputation
			let payload = {
				arbiter_address: arbiter.address,
				appealed: true
			};
			let objMessage = {
				app: "data",
				payload_location: "inline",
				payload_hash: objectHash.getBase64Hash(payload),
				payload: payload
			};
			res = await headlessWallet.sendMultiPayment({
				paying_addresses: [arbstoreFirstAddress],
				messages: [objMessage],
				change_address: arbstoreFirstAddress
			});
			device.sendMessageToDevice(arbiter.device_address, "text", texts.appeal_resolved_arbiter(contract.hash, contract.contract.title, 3*conf.AppealFeeAmount));
			ctx.body = 'ok';
			await contracts.updateStatus(contract.hash, "appeal_approved");
		} catch(e) {
			ctx.throw(403, `{"error": "${e}"}`);
		}
	} else {
		await contracts.updateStatus(contract.hash, "appeal_declined");
	}
	device.readCorrespondentsByDeviceAddresses([appellant_device_address], rows => {
		rows.forEach(row => {
			device.sendMessageToDevice(row.device_address, "arbiter_contract_update", {hash: contract.hash, field: "status", value: (action === 'approve' ? "appeal_approved" : "appeal_declined")});
			//device.sendMessageToDevice(row.device_address, "text", texts.appeal_resolved(contract.hash, contract.contract.title));
		});
	});

	contract = await contracts.get(hash); // re-request updated contract from DB
	contract.arbiter = arbiter;

	await ctx.render('moderator_contract', contract);
});

// Obyte Wallet routes
walletApiRouter.get('/arbiter/:address', async ctx => {
	let address = ctx.params['address'];
	if (!address)
		return ctx.throw(404);
	let arbiter = await arbiters.getByAddress(address);
	if (!arbiter)
		return ctx.throw(404, `address not found`);
	ctx.body = {real_name: arbiter.real_name, device_pub_key: arbiter.info.pairing_code.split('@')[0]};
});

walletApiRouter.post('/dispute/new', async ctx => {
	let request = ctx.request.body;
	if (!request.contract_hash || !request.my_address || !request.peer_address || typeof request.me_is_payer === "undefined" || !request.my_pairing_code || !request.peer_pairing_code || !request.encrypted_contract || !request.unit)
		return ctx.throw(404, `{"error": "not all fields present"}`);
	let contract = await contracts.get(request.contract_hash);
	if (!contract) { // no sniped contract were created, probably because arbbiter was on another arbsotre atm of contract creation
		contract = await extractContractFromUnit(request.unit).catch((err) => {ctx.throw(404, `{"error": "${err}"}`);});
		if (!contract)
			return ctx.throw(404, `{"error": "hash not found"}`);
	}
	if (!((request.my_address === contract.side1_address && request.peer_address === contract.side2_address) ||
		  (request.my_address === contract.side2_address && request.peer_address === contract.side1_address)) ) {
		return ctx.throw(404, `{"error": "addresses do not match definition"}`);
	}
	if (contract.status != "active")
		return ctx.throw(404, `{"error": "contract was in dispute already"}`);
	let balances = await contracts.queryBalance(contract.hash);
	//if (balances[contract.asset] < contract.amount)
	//	return ctx.throw(200, JSON.stringify({error: '{"error": "not enough balance on the contract"}'}));
	if (!contract.amount && !contract.asset) {
		await contracts.updateField("amount", contract.hash, request.amount);
		await contracts.updateField("asset", contract.hash, request.asset);
	} else {
		request.amount = contract.amount;
		request.asset = contract.asset;
	}
	request.arbiter_address = contract.arbiter_address;
	request.service_fee_asset = conf.asset || "base";
	await contracts.updateStatus(contract.hash, "dispute_requested");
	await contracts.updateField("plaintiff_pairing_code", contract.hash, request.my_pairing_code);
	await contracts.updateField("peer_pairing_code", contract.hash, request.peer_pairing_code);
	await contracts.updateField("plaintiff_side", contract.hash, request.my_address === contract.side1_address ? 1 : 2);
	let arbiter = await arbiters.getByAddress(contract.arbiter_address);
	device.sendMessageToDevice(arbiter.device_address, "arbiter_dispute_request", request);
	
	ctx.body = `"ok"`;
});

walletApiRouter.post('/appeal/new', async ctx => {
	let request = ctx.request.body;
	if (!request.contract_hash || !request.my_pairing_code || !request.my_address || !request.contract || !request.contract.title || !request.contract.text)
		return ctx.throw(404, `{"error": "not all fields present"}`);
	let contract = await contracts.get(request.contract_hash);
	if (!contract) {
		if (!contract)
			return ctx.throw(404, `{"error": "hash not found"}`);
	}
	if (contract.status != "dispute_resolved")
		return ctx.throw(404, `{"error": "contract wasn't in dispute"}`);
	await contracts.updateStatus(contract.hash, "appeal_requested");
	await contracts.updateField("contract", contract.hash, JSON.stringify(request.contract));

	if (request.my_pairing_code !== contract.plaintiff_pairing_code && request.my_pairing_code !== contract.peer_pairing_code)
		return ctx.throw(404, `{"error": "wrong pairing code"}`);

	var matches = request.my_pairing_code.match(/^([\w\/+]+)@([\w.:\/-]+)#(.+)$/);
	if (!matches)
		return ctx.throw(404, `{"error": "invalid pairing code"}`);
	var pubkey = matches[1];
	var hub = matches[2];
	var pairing_secret = matches[3];
	if (pubkey.length !== 44)
		return ctx.throw(404, `{"error": "invalid pubkey length"}`);
	device.addUnconfirmedCorrespondent(pubkey, hub, 'New', function(device_address){
		appellant_device_address = device_address;
		device.startWaitingForPairing(function(reversePairingInfo){
			device.sendPairingMessage(hub, pubkey, pairing_secret, reversePairingInfo.pairing_secret, {
				ifOk: () => {
					headlessWallet.issueNextMainAddress(async address => {
						await contracts.updateField("appeal_fee_address", contract.hash, address);
						device.sendMessageToDevice(device_address, 'text', texts.payAppealFee(conf.AppealFeeAmount, address));
					});
				},
				ifError: (err) => {
					ctx.throw(404, `{"error": "${err}"}`);
				}
			});
		});
	});

	let arbiter = await arbiters.getByAddress(contract.arbiter_address);
	device.sendMessageToDevice(arbiter.device_address, "text", texts.appeal_started(request.contract.title));
	
	ctx.body = `"ok"`;
});

walletApiRouter.all('/get_device_address', async ctx => {
	ctx.body = `"${device.getMyDeviceAddress()}"`;
});
walletApiRouter.all('/get_appeal_fee', async ctx => {
	ctx.body = JSON.stringify({amount: conf.AppealFeeAmount, asset: conf.asset});
});

// ArbStore Web JSON API
apiRouter.use(async (ctx, next) => {ctx.useJSON = true;await next()});
apiRouter.get('/languages', ctx => {
	ctx.body = available_languages;
})
apiRouter.get('/tags', ctx => {
	ctx.body = conf.available_tags;
})
apiRouter.get('/pairing_link', ctx => {
	const protocol = process.env.devnet ? 'obyte-dev:' : (process.env.testnet ? 'obyte-tn:' : 'obyte:');
	ctx.body = {pairing_link: protocol + device.getMyDevicePubKey() + "@" + conf.hub + "#" + conf.permanent_pairing_secret};
})
apiRouter.use(router.routes());

// Mount all routes

app.use(mount('/api/v1', apiRouter.routes()));
app.use(walletApiRouter.routes());
app.use(moderatorRouter.routes());
app.use(router.routes());

app.listen(conf.ArbStoreWebPort, () => console.log(`ArbStoreWeb listening on port ${conf.ArbStoreWebPort}!`));
eventBus.once('headless_wallet_ready', onReady);

process.on('unhandledRejection', (reason, promise) => { console.error('unhandled rejection in: ', promise); throw reason; });