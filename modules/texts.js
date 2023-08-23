/*jslint node: true */
'use strict';
const conf = require('ocore/conf');
const constants = require('ocore/constants');

exports.greetings = () => {
	return `Hello, this bot will help you signup as arbiter. For detailed instructions please refer to the arbiter guide https://arbstore.org/arb-guide.

To start, please send me your address (use the "..." menu next to the text input). The address should be attested through Real Name Attestation bot.

For the list of available commands type [help](command:help).`;
};

exports.not_attested = () => {
	return "This address is not attested, attest through Real Name Attestation Bot first. You can find the bot in the Bot Store in your wallet (in the Chat tab).";
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
	return `Now you need to top up your arbiter's deposit. The deposit serves as a safeguard in case an appeal to your decision is raised and your decision is deemed invalid by a moderator of this ArbStore. You can withdraw your deposit any time if you want to unlist yourself from the ArbStore. [Pay ${amount} to ${address}](obyte:${address}?amount=${amount}&asset=${encodeURIComponent(conf.asset || 'base')})`;
}

exports.received_payment = (amount) => {
	return `Received ${formatAmount(amount)} from you, please wait till the payment is confirmed`;
}

exports.payment_confirmed = () => {
	return `Payment confirmed`;
}

exports.request_pairing_code = () => {
	return `Now please send your permanent pairing code for users to be able to pair with you. [Send permanent pairing code](pairing-code:true)`;
}

exports.unit_posted = (unit) => {
	return `Your announcement unit has been posted into the DAG: https://${process.env.testnet ? 'testnet' : ''}explorer.obyte.org/#${unit}\nCongratulations, your arbiter profile is now set up and will appear on the arbiter list in a few minutes.`
}

exports.signMessage = (user_address) => {
	return `I'm going to register as arbiter with my address ${user_address}`;
}

exports.withdraw_completed = (amount, unit, address) => {
	return `Sent ${formatAmount(amount)} from your deposit to address ${address}. https://${process.env.testnet ? 'testnet' : ''}explorer.obyte.org/#${unit}`;
}

exports.already_announced = () => {
	return `You have already been announced as arbiter, no need to sign the message again`;
}

exports.serviceFeeSet = (hash, shared_address, amount) => {
	return `Your fee for resolving the dispute on contract ${hash} (address ${shared_address}) is set to ${formatAmount(amount)}.\n\nA payment request was sent to the plaintiff. We will notify you when the payment is received.\n\nYou are supposed to start working on the dispute only after the ArbStore receives the payment from the plaintiff. The ArbStore will forward this payment to you after you post your decision on the dispute.`;
}

exports.payForArbiterService = (real_name, amount, address, pairing_code, comment) => {
	return `Arbiter ${real_name} is asking ${formatAmount(amount)} for their service of resolving a dispute. Please pay [Pay ${formatAmount(amount)} to ${address}](obyte:${address}?amount=${amount}&asset=${encodeURIComponent(conf.asset || 'base')}).\nIf you wish to discuss the cost with the arbiter, you can pair with them: [arbiter](obyte:${pairing_code})` + (comment ? `\n\nArbiter's comment: ${comment}` : ``) + `\n\nThe arbiter will start working on the case only after you pay.`;
}

exports.service_fee_paid = (hash, shared_address, amount) => {
	return `We received a ${formatAmount(amount)} payment from the plaintiff for the resolution of the dispute on contract ${hash} (contract address ${shared_address}). We will hold it until you resolve this dispute by clicking buttons in the dispute view.`;
}

exports.service_fee_paid_plaintiff = (hash, shared_address, amount) => {
	return `We received your payment of ${formatAmount(amount)} for resolution of the dispute concerning contract ${hash} (contract address ${shared_address}). Please wait for it to stabilize.`;
}

exports.service_fee_stabilized = () => {
	return 'Your payment has stabilized. Arbiter can now resolve this dispute.';
}

exports.appeal_started = (title) => {
	return `We received an appeal to your decision on contract "${title}"`;
}

exports.payAppealFee = (amount, address) => {
	return `Moderator is asking ${formatAmount(amount)} for their service of resolving your appeal. [Pay ${formatAmount(amount)} to ${address}](obyte:${address}?amount=${amount}&asset=${encodeURIComponent(conf.asset || 'base')})`;
}

exports.appeal_fee_paid = (hash, title) => {
	return `Appeal fee received for contract "${title}" with hash ${hash}. You can resolve it now.`;
}

exports.appeal_fee_paid_appellant = (hash, title) => {
	return `Appeal fee received for contract "${title}" with hash ${hash}. Moderator can now resolve it.`;
}

exports.appeal_resolved_arbiter = (hash, title, appeal_fee) => {
	return `The appeal for contract "${title}" with hash ${hash} has been approved. The appeal fee ${formatAmount(appeal_fee)} got deducted from your deposit to compensate for the incorrect decision. Please check that your arbiter listing is still visible using [status](command:status) command and follow the instructions.`;
}

exports.appeal_resolved = (hash, title) => {
	return `The appeal for contract "${title}" with hash ${hash} has been approved.`;
}

exports.contract_completed = (hash, shared_address) => {
	return `The contract ${hash} (contract address ${shared_address}) has been completed by the contract parties.`;
}

exports.service_fee_sent = (hash, shared_address, amount, cut, unit) => {
	const cutText = cut ? `(we charged the ${cut * 100}% ArbStore cut from the money paid by the plaintiff) ` : '';
	return `We deposited ${formatAmount(amount)} to your deposit address ${cutText}for resolving contract ${hash} (contract address ${shared_address}), unit: https://${process.env.testnet ? 'testnet' : ''}explorer.obyte.org/#${unit}\n\nType [help](command:help) to see how to withdraw the funds.`;	
}

exports.not_enough_funds = (amount) => {
	return `You don't have enough funds to withdraw. Current deposit amount is ${formatAmount(amount)}`;
}

exports.unrecognized_command = () => {
	return `Unrecognized command. For the list of available commands type [help](command:help).`;
}


exports.help = () => {
	return `Available commands:
[status](command:status) - your current status
[help](command:help) - this text
[edit info](command:edit info) - edit your bio, specializations, other info (give me the web link!)
[suspend](command:suspend) - shut down your listing from arbiters list
[live](command:live) - resume your listing
[withdraw](command:withdraw) - transfer the funds from your deposit to your address, leaving only minimal amount required
[withdraw all](command:withdraw all) - transfer all the funds from your deposit to your address, also stops the listing
[revive](command:revive) - re-announce your listing on this ArbStore (in case you moved to some other ArbStore and want to go back to this one)

For detailed instructions about signing up and resolving disputes please refer to the arbiter guide https://arbstore.org/arb-guide.`;
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