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
exports.logToSTDOUT = false;
exports.bNoPassphrase = false;

// smtp https://github.com/byteball/ocore/blob/master/mail.js
exports.smtpTransport = 'local'; // use 'local' for Unix Sendmail
exports.smtpRelay = '';
exports.smtpUser = '';
exports.smtpPassword = '';
exports.smtpSsl = null;
exports.smtpPort = null;

// email setup
exports.admin_email = '';
exports.from_email = '';

// ArbStoreWeb
exports.ArbStoreWebPort = (process.env.testnet || process.env.devnet) ? 9003 : 9002;
exports.ArbStoreWebURI = process.env.devnet ? 'http://localhost:' + exports.ArbStoreWebPort + '/' : (process.env.testnet ? 'https://testnet.arbstore.org/' : 'https://arbstore.org/');
exports.WebTokenSalt = 'changemeASAP';
exports.ModeratorDeviceAddresses = [];

exports.asset = process.env.devnet ? '9EEnyOvsMgh8SkPvsRkIiNhSXwvplZk1/8Nr0h17jUw=' : (process.env.testnet ? 'CPPYMBzFzI4+eMk7tLMTGjLF4E60t5MUfo2Gq7Y6Cn4=' : '0IwAk71D5xFP0vTzwamKBwzad3I1ZUjZ1gdeB5OnfOg=');
exports.AppealFeeAmount = 100e4;
exports.min_deposit = 3 * exports.AppealFeeAmount + (exports.asset === 'base' || !exports.asset ? 10000 : 0); // usually ~3xAppealFeeAmount

exports.ArbStoreArbiterCut = 0.1; //a cut taken from each arbiter's service payment in favor of ArbStore
exports.ArbStoreCut = 0.0075; //a cut taken from each contract in favor of ArbStore

exports.trustedAttestorAddresses = process.env.devnet ? ['LJS2XD3M6XR4CBH44DQW7TCWYTYABTG4'] : (process.env.testnet ? ['7JJMSQDS7VG2F5XO23BAUSA5IZ35XBCN'] : ['I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT', 'OHVQ2R5B6TUR5U7WJNYLP3FIOSR7VCED', 'JFKWGRMXP3KHUAFMF4SJZVDXFL6ACC6P']);

// Tags
exports.available_tags = [
	'Export/Import',
	'Domains',
	'Cryptocurrency exchange',
	'IT services',
	'Financial services',
	'Real estate',
	'Vehicles',
	'Collectibles',
	'Art',
];

// Arbiters reputation to be pulled from other arbstores, place it addresses here
exports.ArbStoreAddresses = [];

