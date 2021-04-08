/*jslint node: true */
"use strict";
exports.port = null;
//exports.myUrl = 'wss://mydomain.com/bb';
exports.bServeAsHub = false;
exports.bLight = false;

exports.storage = 'sqlite';

// TOR is recommended.  If you don't run TOR, please comment the next two lines
//exports.socksHost = '127.0.0.1';
//exports.socksPort = 9050;

exports.hub = process.env.testnet ? 'obyte.org/bb-test' : (process.env.devnet ? 'arbregistry.ngrok.io' : 'obyte.org/bb');
exports.deviceName = 'ArbStore';
exports.permanent_pairing_secret = '0000';
exports.control_addresses = [''];
exports.payout_address = 'WHERE THE MONEY CAN BE SENT TO';

//exports.bIgnoreUnpairRequests = true;
exports.bSingleAddress = false;
exports.bStaticChangeAddress = true;
exports.KEYS_FILENAME = 'keys.json';
exports.logToSTDOUT = true;
exports.bNoPassphrase = true;

// smtp https://github.com/byteball/ocore/blob/master/mail.js
exports.smtpTransport = 'local'; // use 'local' for Unix Sendmail
exports.smtpRelay = '';
exports.smtpUser = '';
exports.smtpPassword = '';
exports.smtpSsl = null;
exports.smtpPort = null;

// email setup
exports.admin_email = 'admin@yandex.ru';
exports.from_email = 'admin@yandex.ru';

// ArbStoreWeb
exports.ArbStoreWebProto = 'http';
exports.ArbStoreWebDomain = 'localhost';
exports.ArbStoreWebPort = 9003;
exports.ArbStoreWebURI = `${exports.ArbStoreWebProto}://${exports.ArbStoreWebDomain}:${exports.ArbStoreWebPort}/`;
exports.WebTokenSalt = 'changemeASAP';
exports.ModeratorDeviceAddresses = ['0FRHQZIUM32IIZJX22WRL3F6BRYKQDWUD', '04MUXB6RXQMKVCWNQOQ3SCW2WTJN43NM3'];
exports.AppealFeeAmount = 10000;
exports.min_deposit = 3*exports.AppealFeeAmount + 10000; // usually ~3xAppealFeeAmount

exports.trustedAttestorAddresses = ['LJS2XD3M6XR4CBH44DQW7TCWYTYABTG4'];

// Tags
exports.available_tags = [
	'IT',
	'Insurance',
	'Finance',
	'Real estate'
];

