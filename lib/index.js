"use strict";

const _ = require('lodash');
const debug = require('debug')('loopback:component:sacl');
const SG = require('strong-globalize');
SG.SetRootDir(require('path').join(__dirname, '..'));
const Promise = require('bluebird');
const Security = require('./security');

module.exports = function (app, options) {
	debug('initializing component');

	const loopback = app.loopback;
	const loopbackMajor = loopback && loopback.version &&
		loopback.version.split('.')[0] || 1;

	if (loopbackMajor < 2) {
		throw new Error('loopback-component-sacl requires loopback 2.0 or newer');
	}

	app.middleware('auth:after', require('./current-user-context')());

	const sec = new Security(app, options);

	app.sec = sec;
	app.acl = sec.acl;

	if (options.security === false) {
		// disable security
		return;
	}

	Promise.each([
		require('./security/build'),
		require('./security/load-abilities'),
		require('./security/role-resolver'),
		require('./security/filters'),
		require('./security/auto-add-roles'),
		require('./security/auto-add-permissions'),
	], fn => fn(sec));
};
