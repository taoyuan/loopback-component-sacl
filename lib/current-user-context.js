'use strict';

const debug = require('debug')('loopback:component:sacl:user-context');
const Promise = require('bluebird');
const LoopbackContext = require('loopback-context');
const _ = require('lodash');

module.exports = function () {
	debug('initializing current user context middleware');
	// set current user to enable user access for remote methods
	return function setCurrentUser(req, res, next) {
		const loopbackContext = LoopbackContext.getCurrentContext();
		if (!loopbackContext) {
			console.warn(`No user context (loopback current context not found)`);
			return next();
		}

		if (!req.accessToken) {
			// debug('No user context (access token not found)');
			return next();
		}

		loopbackContext.set('accessToken', req.accessToken.id);
		debug(`User Context Middleware - Token Id: "${req.accessToken.id}", Token User Id: "${req.accessToken.userId}"`)

		const app = req.app;
		const UserModel = app.registry.getModel(app.sec.opts.userModel || 'User');

		return Promise.resolve(UserModel.findById(req.accessToken.userId)).then(user => {
			if (!user) {
				return next(new Error('No user with this access token was found.'));
			}
			loopbackContext.set('currentUser', user);
			debug('Current User: %j', user);
		}).nodeify(next);
	};
};
