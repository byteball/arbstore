/*jslint node: true */
'use strict';
const conf = require('ocore/conf');

exports.greetings = () => {
	return `Hello, this bot can help you attest yourself as an arbiter.
To start, send me your address. Address should be attested through Real Name Attestation bot.`;
};

exports.not_attested = () => {
	return "This address is not attested, attest through Real Name Attestation Bot first";
};

exports.reveal_profile = () => {
	return `[Reveal your real name](profile-request:first_name,last_name) to reveal your real name to users
or [stay anonymous](command:stay anonymous)`;
};

exports.already_registered_from_different_address = () => {
	return "You were already registered as arbiter from another address";
}

exports.device_address_unknown = () => {
	return "Your device is unknown. Please, register first";
}

exports.topup_deposit = (amount, address) => {
	return `Now you need to topup your arbiter's deposit. [Pay ${amount} to ${address}](obyte:${address}?amount=${amount})`;
}

exports.received_payment = (amount) => {
	return `Received ${amount/1e9} GB from you, please wait till it confirmed`;
}

exports.payment_confirmed = () => {
	return `Payment confirmed`;
}

exports.request_pairing_code = () => {
	return `Transaction confirmed. Now we need your permanent pairing code for users to be able to pair with you. [Send permanent pairing code](pairing-code:true)`;
}

exports.unit_posted = (unit) => {
	return `Your announcement unit was posted into DAG: https://explorer.obyte.org/#${unit}\nYou are now set up.`
}

exports.signMessage = (user_address) => {
	return `I'm going to register as arbiter with my address ${user_address}`;
}

exports.withdraw_completed = (unit, address) => {
	return `Sent all bytes from your deposit to address ${address}. https://explorer.obyte.org/#${unit}`;
}

exports.already_announced = () => {
	return `You were already announced as arbiter, no need to sign message again`;
}

exports.serviceFeeSet = (hash, amount) => {
	return `Your fee for resolving dispute on contract ${hash} is set to ${amount} bytes. Payment request is sent to plaintiff. We will notify you when payment is received.`;
}

exports.payForArbiterService = (amount, address) => {
	return `Arbiter is asking ${amount} bytes for his service of resolving a dispute. Please [Pay ${amount} to ${address}](obyte:${address}?amount=${amount})`;
}

exports.service_fee_paid = (hash, amount) => {
	return `We received a payment from plaintiff of total ${amount} bytes for contract ${hash}. Post your dispute resolution in the form of data feed with the name 'CONTRACT_${hash}' and value of winning side address`;
}

exports.appeal_started = (title) => {
	return `We received an appeal to your decision on contract ${title}`;
}

exports.payAppealFee = (amount, address) => {
	return `Moderator is asking ${amount} bytes for his service of resolving your appeal. Please [Pay ${amount} to ${address}](obyte:${address}?amount=${amount})`;
}

exports.appeal_fee_paid = (hash, title) => {
	return `Appeal fee received for contract ${title} with hash ${hash}. You can resolve it now.`;
}

exports.appeal_resolved_arbiter = (hash, title) => {
	return `Appeal for contract ${title} with hash ${hash} was resolved, Appeal fee got deducted from your deposit to compensate your incorrect decision. Please check that your arbiter listing is visible using 'status' command and follow instructions.`;
}

exports.appeal_resolved = (hash, title) => {
	return `Appeal for contract ${title} with hash ${hash} was resolved.`;
}


exports.help = () => {
	return `Available commands:
[status](command:status) – your current status
[help](command:help) - this text
[edit_info](command:edit_info) - tdit your bio, specializations, other info (give me the web link!)
[suspend](command:suspend) - shut down your listing from arbiters list
[live](command:live) - resume your listing
[withdraw](command:withdraw) - transfer all the funds from your deposit to your address, also stops the listing
[revive](command:revive) - re-announce your listing on this ArbStore (in case you moved to some other ArbStore and want to go back on this one)`;
};

exports.current_status = (arbiter) => {
	let text = 'For list of available commands, type [help](command:help)\n\n';
	if (!arbiter.visible)
		text += `You are currently invisible in arbiters list. To change this, type [live](command:live) or [edit_info](command:edit_info).\n`;
	text += `Your deposit balance is: ${arbiter.balance} bytes.\n`;
	if (arbiter.balance < conf.min_deposit)
		text += `Your listing is not showing in arbiters list, because you have not sufficient funds in your deposit. To add bytes, type [revive](command:revive)\n`;
	if (!arbiter.enabled)
		text += `You have been disabled by moderator. Contact the ArbStore to resolve it`;
	return text;
};

//errors
exports.errorInitSql = () => {
	return 'please import db.sql file\n';
};

exports.errorEmail = () => {
	return `please specify admin_email and from_email in your ${desktopApp.getAppDataDir()}/conf.json\n`;
};
