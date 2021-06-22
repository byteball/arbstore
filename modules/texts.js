/*jslint node: true */
'use strict';
const conf = require('ocore/conf');
const constants = require('ocore/constants');

exports.greetings = () => {
	return `Hello, this bot can help you signup as an arbiter.
To start, send me your address. The address should be attested through Real Name Attestation bot.

For the list of available commands type [help](command:help).`;
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
	return "Your device is unknown. Please register first";
}

exports.topup_deposit = (amount, address) => {
	return `Now you need to topup your arbiter's deposit. The deposit serves as a safeguard in case an appeal to your decision is raised and your decision is deemed invalid by a moderator of this ArbStore. You can withdraw your deposit any time if you want to unlist yourself from the ArbStore. [Pay ${amount} to ${address}](obyte:${address}?amount=${amount}&asset=${encodeURIComponent(conf.asset || 'base')})`;
}

exports.received_payment = (amount) => {
	return `Received ${formatAmount(amount)} from you, please wait till the payment is confirmed`;
}

exports.payment_confirmed = () => {
	return `Payment confirmed`;
}

exports.request_pairing_code = () => {
	return `Transaction confirmed. Now we need your permanent pairing code for users to be able to pair with you. [Send permanent pairing code](pairing-code:true)`;
}

exports.unit_posted = (unit) => {
	return `Your announcement unit was posted into DAG: https://${process.env.testnet ? 'testnet' : ''}explorer.obyte.org/#${unit}\nYou are now set up.`
}

exports.signMessage = (user_address) => {
	return `I'm going to register as arbiter with my address ${user_address}`;
}

exports.withdraw_completed = (amount, unit, address) => {
	return `Sent ${formatAmount(amount)} from your deposit to address ${address}. https://${process.env.testnet ? 'testnet' : ''}explorer.obyte.org/#${unit}`;
}

exports.already_announced = () => {
	return `You were already announced as arbiter, no need to sign the message again`;
}

exports.serviceFeeSet = (hash, amount) => {
	return `Your fee for resolving the dispute on contract ${hash} is set to ${formatAmount(amount)}. A payment request was sent to the plaintiff. We will notify you when the payment is received.`;
}

exports.payForArbiterService = (real_name, amount, address, pairing_code, comment) => {
	return `Arbiter ${real_name} is asking ${formatAmount(amount)} for their service of resolving a dispute. [Pay ${formatAmount(amount)} to ${address}](obyte:${address}?amount=${amount}&asset=${encodeURIComponent(conf.asset || 'base')}).\nIf you wish to discuss the cost with the arbiter, you can pair with them: [arbiter](obyte:${pairing_code})` + (comment ? `\n\nArbiter's comment: ${comment}` : ``);
}

exports.service_fee_paid = (hash, amount) => {
	return `We received a ${formatAmount(amount)} payment from the plaintiff for the resolution of the dispute on contract ${hash}. We will hold it until you resolve this dispute by clicking buttons in the dispute view.`;
}

exports.service_fee_paid_plaintiff = (hash, amount) => {
	return `We received a payment from you of total ${formatAmount(amount)} for contract ${hash}. Wait for it to stabilize.`;
}

exports.service_fee_stabilized = () => {
	return 'Your payment is stabilized. Arbiter can now resolve this dispute.';
}

exports.appeal_started = (title) => {
	return `We received an appeal to your decision on contract ${title}`;
}

exports.payAppealFee = (amount, address) => {
	return `Moderator is asking ${formatAmount(amount)} for their service of resolving your appeal. [Pay ${formatAmount(amount)} to ${address}](obyte:${address}?amount=${amount}&asset=${encodeURIComponent(conf.asset || 'base')})`;
}

exports.appeal_fee_paid = (hash, title) => {
	return `Appeal fee received for contract ${title} with hash ${hash}. You can resolve it now.`;
}

exports.appeal_fee_paid_appellant = (hash, title) => {
	return `Appeal fee received for contract ${title} with hash ${hash}. Moderator can now resolve it.`;
}

exports.appeal_resolved_arbiter = (hash, title, appeal_fee) => {
	return `The appeal for contract ${title} with hash ${hash} was approved. The appeal fee ${formatAmount(appeal_fee)} got deducted from your deposit to compensate for incorrect decision. Please check that your arbiter listing is still visible using 'status' command and follow the instructions.`;
}

exports.appeal_resolved = (hash, title) => {
	return `The appeal for contract ${title} with hash ${hash} was approved.`;
}

exports.contract_completed = (hash) => {
	return `The contract with hash ${hash} was completed by contract parties.`;
}

exports.service_fee_sent = (hash, amount, cut, unit) => {
	return `We deposited ${formatAmount(amount)} to your deposit address (we charged the ${cut*100}% ArbStore cut from the money paid by plaintiff) for resolving contract ${hash}, unit: https://${process.env.testnet ? 'testnet' : ''}explorer.obyte.org/#${unit}`;	
}

exports.not_enough_funds = (amount) => {
	return `You don't have enough funds to withdraw. Current deposit amount is ${formatAmount(amount)}`;
}

exports.unrecognized_command = () => {
	return `Unrecognized command. For the list of available commands type [help](command:help).`;
}


exports.help = () => {
	return `Available commands:
[status](command:status) – your current status
[help](command:help) - this text
[edit info](command:edit info) - edit your bio, specializations, other info (give me the web link!)
[suspend](command:suspend) - shut down your listing from arbiters list
[live](command:live) - resume your listing
[withdraw](command:withdraw) - transfer the funds from your deposit to your address, leaving only minimal amount required
[withdraw all](command:withdraw all) - transfer all the funds from your deposit to your address, also stops the listing
[revive](command:revive) - re-announce your listing on this ArbStore (in case you moved to some other ArbStore and want to go back on this one)`;
};

exports.current_status = (arbiter) => {
	let text = 'For the list of available commands, type [help](command:help)\n\n';
	text += `Your deposit balance is: ${formatAmount(arbiter.balance)}.\n\n`;
	if (!arbiter.enabled)
		text += `You have been disabled by moderator. Contact the ArbStore to resolve it\n\n`;
	else if (!arbiter.visible)
		text += `You are currently invisible in the arbiters list. To change this, type [live](command:live) or [edit_info](command:edit_info).\n\n`;
	else if (arbiter.balance < conf.min_deposit)
		text += `Your listing is not showing in arbiters list because you don't have enough funds on your deposit. To add funds, type [revive](command:revive)\n\n`;
	else
		text += `Your arbiter listing is active.`;
	return text;
};

//errors
exports.errorInitSql = () => {
	return 'please import db.sql file\n';
};

exports.errorEmail = () => {
	return `please specify admin_email and from_email in your ${desktopApp.getAppDataDir()}/conf.json\n`;
};

exports.assetMetadata = null; // will be set in main file
function formatAmount(amount) {
	if (conf.asset) {
		if (conf.asset === constants.BLACKBYTES_ASSET)
			return `${amount/1e9} GBB`;
		if (exports.assetMetadata) {
			let decimals = exports.assetMetadata.decimals || 0;
			return `${(amount / Math.pow(10, decimals)).toLocaleString([], {maximumFractionDigits: decimals})} ${exports.assetMetadata.name}`;
		}
		return `${amount} of ${conf.asset}`
	}
	return `${amount/1e9} GB`;
}