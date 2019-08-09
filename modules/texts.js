/*jslint node: true */
'use strict';
exports.greetings = () => {
	return "Hello, send me your address.";
};

exports.not_attested = () => {
	return "This address is not attested, attest through Real Name Attestation Bot first";
};

exports.reveal_profile = () => {
	return `[Reveal your real name](profile-request:first_name,last_name) to reveal your real name to users
or [stay anonymous](command:stay_anonymous)`;
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
	return `Your announcement unit was posted into DAG: https://explorer.obyte.org/#${unit}\nYou're are now set up.`
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

exports.help = () => {
	return "Help text";
};

//errors
exports.errorInitSql = () => {
	return 'please import db.sql file\n';
};

exports.errorEmail = () => {
	return `please specify admin_email and from_email in your ${desktopApp.getAppDataDir()}/conf.json\n`;
};
