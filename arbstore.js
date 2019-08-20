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
const device = require('ocore/device.js');
const privateProfile = require('ocore/private_profile.js');
const headlessWallet = require('headless-obyte');

const Koa = require('koa');
const app = new Koa();
const views = require('koa-views');
const KoaRouter = require('koa-router');
const bodyParser = require('koa-bodyparser');
const router = new KoaRouter();


let available_languages = {};
fs.readFile('languages.json', 'utf8', function(err, contents) {
	available_languages = JSON.parse(contents);
});

function onReady() {
	eventBus.on('paired', from_address => {
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
		})
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
		}
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
			{pattern: /\(profile:(.+?)\)|stay_anonymous/, action: async (arrProfileMatches) => {
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
			{pattern: /^([\w\/+]+)@([\w.:\/-]+)#(.+)$/, action: async matches => {
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
				let network = require('ocore/network.js');
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
			{pattern: /.*/, action: () => respond(texts.greetings())}
		]);
	});
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

	const network = require('ocore/network.js');
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

eventBus.on('new_my_transactions', async arrUnits => {
	let rows = await db.query(
		`SELECT SUM(amount) as amount, hash
		FROM outputs
		CROSS JOIN arbiters ON outputs.address=arbiters.deposit_address
		WHERE unit IN(?) AND asset IS NULL
		GROUP BY deposit_address`, [arrUnits]);
	rows.forEach(async row => {
		let amount = row.amount;
		let arbiter = await arbiters.getByHash(row.hash);
		device.sendMessageToDevice(arbiter.device_address, 'text', texts.received_payment(amount));
	});
});

eventBus.on('my_transactions_became_stable', async arrUnits => {
	let rows = await db.query(
		`SELECT hash
		FROM outputs
		CROSS JOIN arbiters ON outputs.address=arbiters.deposit_address
		WHERE unit IN(?) AND asset IS NULL
		GROUP BY deposit_address`, [arrUnits]);
	rows.forEach(async row => {
		let arbiter = await arbiters.getByHash(row.hash);
		device.sendMessageToDevice(arbiter.device_address, 'text', texts.payment_confirmed());
		checkDeposit(row.hash);
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

router.get('/thankyou.html', async ctx => {
	await ctx.render('thankyou');
});
router.get('/:token', async ctx => {
	let token = ctx.params['token'];
	if (!token)
		return;
	let hash = decryptWebToken(token) || ctx.cookies.get('hash');
	if (!hash)
		return ctx.body = `invalid token`;
	let arbiter = await arbiters.getByHash(hash);
	if (!arbiter)
		return ctx.body = `hash not found`;
	
	ctx.cookies.set('hash', arbiter.hash);

	arbiter.available_tags = conf.available_tags;
	arbiter.available_languages = available_languages;
	arbiter.error = ctx.query.error;
	arbiter.success = ctx.query.success;

	await ctx.render('index', arbiter);
});
router.post('/:token', async ctx => {
	let token = ctx.params['token'];
	if (!token)
		return;
	let hash = decryptWebToken(token) || ctx.cookies.get('hash');
	if (!hash)
		return ctx.body = `invalid token`;
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
app.use(router.routes());

app.listen(conf.ArbStoreWebPORT, () => console.log(`ArbStoreWeb listening on port ${conf.ArbStoreWebPORT}!`));
eventBus.once('headless_wallet_ready', onReady);

process.on('unhandledRejection', up => { throw up; });
