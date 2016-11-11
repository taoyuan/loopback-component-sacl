"use strict";

const _ = require('lodash');
const debug = require('debug')('loopback:component:sacl');
const SG = require('strong-globalize');
SG.SetRootDir(require('path').join(__dirname, '..'));
const Promise = require('bluebird');
const Security = require('./security');
const remctx = require('./remctx');

module.exports = function (app, options) {
	debug('initializing component');

	const loopback = app.loopback;
	const loopbackMajor = loopback && loopback.version &&
		loopback.version.split('.')[0] || 1;

	if (loopbackMajor < 2) {
		throw new Error('loopback-component-sacl requires loopback 2.0 or newer');
	}

	remctx(app);

	const security = new Security(app, options);

	app.sec = security;
	app.acl = security.acl;

	if (options.security === false) {
		// disable security
		return;
	}

	Promise.each([
		() => security.build(),
		() => security.loadAbilities(),
		() => security.setupRoleResolver(),
		() => security.setupFilters()
	], fn => fn());
};
