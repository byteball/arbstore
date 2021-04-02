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

const Koa = require('koa');
const app = new Koa();
const views = require('koa-views');
const KoaRouter = require('koa-router');
const bodyParser = require('koa-bodyparser');
const router = new KoaRouter();
const moderatorRouter = new KoaRouter();


let available_languages = {};
fs.readFile('languages.json', 'utf8', function(err, contents) {
	available_languages = JSON.parse(contents);
});

let last_plaintiff_device_address = null;
let appellant_device_address = null;

/*
function createAsset(){
	var composer = require('ocore/composer.js');
	var callbacks = composer.getSavingCallbacks({
		ifNotEnoughFunds: console.error,
		ifError: console.error,
		ifOk: async function(objJoint){
			network.broadcastJoint(objJoint);
			console.error('==== Asset ID:'+ objJoint.unit.unit);

		}
	});
	var asset = {
		cap: 2111100000000000,
		//cap: 1000000,
		is_private: false,
		is_transferrable: true,
		auto_destroy: false,
		fixed_denominations: false, // if true then it's IndivisibleAsset, if false then it's DivisibleAsset
		issued_by_definer_only: true,
		cosigned_by_definer: false,
		spender_attested: false,
	//    issue_condition: ["in data feed", [["MO7ZZIU5VXHRZGGHVSZWLWL64IEND5K2"], "timestamp", ">=", 1453139371111]],
	//    transfer_condition: ["has one equal", 
	//        {equal_fields: ["address", "amount"], search_criteria: [{what: "output", asset: "base"}, {what: "output", asset: "this asset"}]}
	//    ],
		//attestors: ["X5ZHWBYBF4TUYS35HU3ROVDQJC772ZMG", "GZSEKMEQVOW2ZAHDZBABRTECDSDFBWVH", "2QLYLKHMUG237QG36Z6AWLVH4KQ4MEY6"].sort()
	};
	headlessWallet.readFirstAddress(function(definer_address){
		composer.composeAssetDefinitionJoint(definer_address, asset, headlessWallet.signer, callbacks);
	});
}

function issueAsset(asset) {
	const divisibleAsset = require('ocore/divisible_asset.js');
	let myAddress = "JDWHTTJTMMOGZULXJCWWDDV4IIEQAMZ6";

	divisibleAsset.composeAndSaveDivisibleAssetPaymentJoint({
		asset: asset,
		paying_addresses: [myAddress],
		fee_paying_addresses: [myAddress],
		change_address: myAddress,
		to_address: myAddress,
		amount: 2111100000000000,
		signer: headlessWallet.signer,
		callbacks: {
			ifError: console.error,
			ifNotEnoughFunds: console.error,
			ifOk: (objJoint) => {
				network.broadcastJoint(objJoint);
				console.error('==== Token issued');
			}
		}
	});
}

function sendAsset(asset) {
	headlessWallet.sendMultiPayment({
		asset: asset,
		to_address: "GF7L477BO6WL2DVJASWRR55TEGCNN5OO",
		amount: 2111100000000000
	});
}
*/

function onReady() {

	//createAsset();
	//==== Asset ID:EgGLYLzrBBro1oq/XmFvemeY/QFnijMwHwxZDwRNjLc=
	//issueAsset("EgGLYLzrBBro1oq/XmFvemeY/QFnijMwHwxZDwRNjLc=");
	//sendAsset("EgGLYLzrBBro1oq/XmFvemeY/QFnijMwHwxZDwRNjLc=");

	
	
	//network.start();
	eventBus.on('paired', from_address => {
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
				`SELECT value FROM attested_fields WHERE address=? AND field='profile_hash'`, [address], resolve);
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
			{pattern: /^edit_info$/, action: async () => {
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
			{pattern: /^withdraw$/, action: async () => {
				if (network.isCatchingUp())
					return respond(`Sync is in progress, try again later`);
				let current_arbiter = await arbiters.getByDeviceAddress(from_address);
				if (!current_arbiter)
					return respond(texts.device_address_unknown());
				try {
					let res = await headlessWallet.sendAllBytesFromAddress(current_arbiter.deposit_address, current_arbiter.address, current_arbiter.device_address);
					respond(texts.withdraw_completed(res.unit, current_arbiter.address));
				} catch(e) {
					respond(`${e}`);
				}
			}},
			{pattern: /^(.{44})\s([\d]+)\s?(.*)$/, action: async matches => { // service fee
				let current_arbiter = await arbiters.getByDeviceAddress(from_address);
				if (!current_arbiter)
					return respond(texts.device_address_unknown());
				let amount = matches[2];
				if (amount <= 0)
					return respond(`incorrect amount`);
				let hash = matches[1];
				let contract = await contracts.get(hash);
				if (!contract)
					return respond(`incorrect contract hash`);
				await contracts.updateField("service_fee", hash, amount);
				let comment = matches[3];
				// pair with plaintiff and send payment request
				var matches = contract.plaintiff_pairing_code.match(/^([\w\/+]+)@([\w.:\/-]+)#(.+)$/);
				if (!matches)
					return respond(`Invalid pairing code`);
				var pubkey = matches[1];
				var hub = matches[2];
				var pairing_secret = matches[3];
				if (pubkey.length !== 44)
					return respond(`Invalid pubkey length`);
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
			{pattern: /.*/, action: async () => {
				let current_arbiter = await arbiters.getByDeviceAddress(from_address);
				if (!current_arbiter)
					respond(texts.greetings());
				else {
					current_arbiter.balance = await arbiters.getDepositBalance(current_arbiter.hash);
					respond(texts.current_status(current_arbiter));
				}
			}}
		]);
	});

	setInterval(async () => {
		let rows = await db.query(`SELECT wac.hash, arbiters.deposit_address, wac.arbiter_address, wac.service_fee_address FROM arbstore_arbiter_contracts AS wac
			JOIN arbiters ON arbiters.address=wac.arbiter_address
			WHERE wac.status IN ('dispute_resolved', 'appeal_resolved', 'appeal_declined')
			AND julianday('now') - julianday(wac.status_change_date) > -1`, []);
		rows.forEach(row => {
			balances.readOutputsBalance(row.service_fee_address, async (assocBalances) => {
				if (assocBalances["base"].stable == 0)
					return;
				try {
					let res = await headlessWallet.sendMultiPayment({
						paying_addresses: [row.service_fee_address],
						to_address: row.deposit_address,
						send_all: true
					});
					let arbiter = await arbiters.getByAddress(row.arbiter_address);
					device.sendMessageToDevice(arbiter.device_address, "text", texts.service_fee_sent(row.hash, assocBalances["base"].stable, res.unit));
				} catch (e) {
					console.warn('error while trying to send payment to arbiter from address '+row.service_fee_address+', balance: ' + assocBalances["base"].total)
					return;
				}
			});
		});
	}, 3*1000);
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
	headlessWallet.readFirstAddress(async address => {
		/*composer.composeJoint({
			paying_addresses: [address],
			outputs: [{address: address, amount: 0}],
			messages: [objMessage],
			signer: headlessWallet.signer, 
			callbacks: composer.getSavingCallbacks({
				ifNotEnoughFunds: onError,
				ifError: onError,
				ifOk: function(objJoint){
					network.broadcastJoint(objJoint);
					onDone(objJoint.unit.unit);
				}
			})
		});*/
		try {
			let res = await headlessWallet.sendMultiPayment({
				paying_addresses: [address],
				messages: [objMessage],
				change_address: address
			});
			db.query(`UPDATE arbiters SET announce_unit=? WHERE hash=?`, [res.unit, arbiter.hash]);
			device.sendMessageToDevice(arbiter.device_address, 'text', texts.unit_posted(res.unit));
		} catch(e) {
			onError(`${e}`);
		}
	});

	/*if (!arbiter.enabled && )
		arbiters.setEnabled(hash, true);*/
}

// deposit topup
eventBus.on('new_my_transactions', async arrUnits => {
	let rows = await db.query(
		`SELECT SUM(outputs.amount) as amount, hash
		FROM outputs
		CROSS JOIN arbiters ON outputs.address=arbiters.deposit_address
		JOIN inputs ON outputs.unit=inputs.unit AND inputs.address=arbiters.address -- only payments from arbiter address
		WHERE outputs.unit IN(?) AND outputs.asset IS NULL
		GROUP BY deposit_address`, [arrUnits]);
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
		JOIN inputs ON outputs.unit=inputs.unit AND inputs.address=arbiters.address -- only payments from arbiter address
		WHERE outputs.unit IN(?) AND outputs.asset IS NULL
		GROUP BY deposit_address`, [arrUnits]);
	rows.forEach(async row => {
		let arbiter = await arbiters.getByHash(row.hash);
	 	device.sendMessageToDevice(arbiter.device_address, 'text', texts.payment_confirmed());
		checkDeposit(row.hash);
	});
});

// service fee paid
eventBus.on('my_transactions_became_stable', async arrUnits => {
	let rows = await db.query(
		`SELECT hash, SUM(outputs.amount) AS amount
		FROM outputs
		CROSS JOIN arbstore_arbiter_contracts AS arb_c ON outputs.address=arb_c.service_fee_address
		WHERE outputs.unit IN(?) AND outputs.asset IS NULL
		GROUP BY service_fee_address`, [arrUnits]);
	rows.forEach(async row => {
		let contract = await contracts.get(row.hash);
		if (contract.status !== "dispute_requested" || row.amount < contract.service_fee) return;
		await contracts.updateStatus(contract.hash, "in_dispute");
		let arbiter = await arbiters.getByAddress(contract.arbiter_address);
	 	device.sendMessageToDevice(arbiter.device_address, 'text', texts.service_fee_paid(contract.hash, row.amount));
	});
});

// appeal fee paid
eventBus.on('my_transactions_became_stable', async arrUnits => {
	let rows = await db.query(
		`SELECT hash, SUM(outputs.amount) AS amount
		FROM outputs
		CROSS JOIN arbstore_arbiter_contracts AS arb_c ON outputs.address=arb_c.appeal_fee_address
		WHERE outputs.unit IN(?) AND outputs.asset IS NULL
		GROUP BY appeal_fee_address`, [arrUnits]);
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
				if (contract.status === 'in_dispute') {
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

router.get('/', async ctx => {
	await ctx.render('index');
});
router.get('/thankyou.html', async ctx => {
	await ctx.render('thankyou');
});
router.get('/list', async ctx => {
	let arbiter_list = await arbiters.getAllVisible();
	await ctx.render('list', {arbiter_list: arbiter_list});
});
let lastPairedAddress = '';
moderatorRouter.get('/checklogin', async ctx => {
	if (!conf.ModeratorDeviceAddresses.includes(lastPairedAddress))
		return ctx.body='false';
	ctx.cookies.set('address', encrypt(lastPairedAddress));
	ctx.redirect('/moderator');
});
moderatorRouter.get('/pair', async ctx => {
	async function waitForPairing() {
		return new Promise(resolve => device.startWaitingForPairing(resolve));
	};
	let pi = await waitForPairing();
	await ctx.render('login', {pairing_code: `${pi.device_pubkey}@${pi.hub}#${pi.pairing_secret}`});
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
	
	if (action === 'approve') {
		let loser = contract.winner_side === 1 ? contract.side2_address : contract.side1_address;

		try {
			let res = await headlessWallet.sendMultiPayment({
				paying_addresses: [arbiter.deposit_address],
				to_address: loser,
				amount: 3*conf.AppealFeeAmount,
				change_address: arbiter.deposit_address
			});
			device.sendMessageToDevice(arbiter.device_address, "text", texts.appeal_resolved_arbiter(contract.hash, contract.contract.title));
			ctx.body = 'ok';
			await contracts.updateStatus(contract.hash, "appeal_approved");
		} catch(e) {
			ctx.throw(403, `{"error": "${e}"}`);
		}
	} else {
		await contracts.updateStatus(contract.hash, "appeal_declined");
	}
	let appellant_device_address;
	if (contract.plaintiff_side != contract.winner_side) {
		appellant_device_address = objectHash.getDeviceAddress(contract.plaintiff_pairing_code.split('@')[0]);
	} else {
		appellant_device_address = objectHash.getDeviceAddress(contract.peer_pairing_code.split('@')[0]);
	}
	device.readCorrespondentsByDeviceAddresses([appellant_device_address], rows => {
		rows.forEach(row => {
			device.sendMessageToDevice(row.device_address, "arbiter_contract_update", {hash: contract.hash, field: "status", value: (action === 'approve' ? "appeal_resolved" : "appeal_declined")});
			//device.sendMessageToDevice(row.device_address, "text", texts.appeal_resolved(contract.hash, contract.contract.title));
		});
	});

	contract = await contracts.get(hash); // re-request updated contract from DB
	contract.arbiter = arbiter;

	await ctx.render('moderator_contract', contract);
});
router.use('/moderator', moderatorRouter.routes());
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
	
	arbiter.available_languages = available_languages;
	await ctx.render('arbiter', arbiter);
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

	arbiter.available_tags = conf.available_tags;
	arbiter.available_languages = available_languages;
	arbiter.error = ctx.query.error;
	arbiter.success = ctx.query.success;

	await ctx.render('edit_arbiter', arbiter);
});
router.post('/:token', async ctx => {
	let token = ctx.params['token'];
	if (!token)
		ctx.throw(404);
	let hash = decryptWebToken(token) || ctx.cookies.get('hash');
	if (!hash)
		ctx.throw(404, `invalid token`);
	let error;
	let is_new_arbiter = true;
	try {
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
		body.languages.forEach(l => {
			if (available_languages[l])
				languages.push(l);
		});
		if (languages.length === 0)
			throw(`Pick at least one language`);

		const info = {
			"bio": body.bio,
			"contact_info": body.contact_info,
			"tags": tags,
			"languages": languages
		}
		let current_arbiter = await arbiters.getByHash(hash);
		
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

router.get('/api/arbiter/:address', async ctx => {
	let address = ctx.params['address'];
	if (!address)
		return ctx.throw(404);
	let arbiter = await arbiters.getByAddress(address);
	if (!arbiter)
		return ctx.throw(404, `address not found`);
	ctx.body = {real_name: arbiter.real_name, device_pub_key: arbiter.info.pairing_code.split('@')[0]};
});

router.post('/api/dispute/new', async ctx => {
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
	await contracts.updateStatus(contract.hash, "dispute_requested");
	await contracts.updateField("plaintiff_pairing_code", contract.hash, request.my_pairing_code);
	await contracts.updateField("peer_pairing_code", contract.hash, request.peer_pairing_code);
	await contracts.updateField("plaintiff_side", contract.hash, request.my_address === contract.side1_address ? 1 : 2);
	let arbiter = await arbiters.getByAddress(contract.arbiter_address);
	device.sendMessageToDevice(arbiter.device_address, "arbiter_dispute_request", request);
	
	ctx.body = `"ok"`;
});

router.post('/api/appeal/new', async ctx => {
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

router.all('/api/get_device_address', async ctx => {
	ctx.body = `"${device.getMyDeviceAddress()}"`;
});

app.use(router.routes());

app.listen(conf.ArbStoreWebPort, () => console.log(`ArbStoreWeb listening on port ${conf.ArbStoreWebPort}!`));
eventBus.once('headless_wallet_ready', onReady);

process.on('unhandledRejection', (reason, promise) => { console.error('unhandled rejection in: ', promise); throw reason; });