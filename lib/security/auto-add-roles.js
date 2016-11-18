"use strict";

const debug = require('debug')('loopback:component:sacl:auto-add-roles');
const g = require('strong-globalize')();
const _ = require('lodash');
const Promise = require('bluebird');
const chalk = require('chalk');
const utils = require('../utils');

const DEFAULT_OWNER_ROLES = ['manager', 'admin'];

module.exports = function (sec) {
	debug(chalk.yellow('Setup Auto Add Roles Observer'));

	const {app} = sec;
	const models = sec.groups;

	models.forEach(model => {
		attachAfterSaveObserver(model);
	});

	// ----------------------------------------------------------------
	//  Internal Functions
	// ----------------------------------------------------------------
	function attachAfterSaveObserver(model) {
		const Model = app.registry.getModel(model);

		if (typeof Model.observe !== 'function') return;

		debug(g.f('Attaching Auto Add Roles Observer to %s'), Model.modelName);

		const modelName = Model.modelName;
		const mni = chalk.blue(modelName);

		Model.observe('after save', (ctx, next) => {
			// only allow default permission for new instance
			if (!ctx.isNewInstance) {
				return next();
			}

			const currentUserId = sec.getCurrentUserId();
			const roles = Object.keys(Model.security.roles);

			debug('%s - Adding roles %j to "%s:%s"', mni, roles, modelName, ctx.instance.id);
			Promise.map(roles, role => sec.acl.Role.sure(role, ctx.instance))
				.then(roles => {
					if (currentUserId) {
						return Promise.filter(roles, role => DEFAULT_OWNER_ROLES.includes(role.name));
					}
				})
				.then(roles => {
					if (roles && roles.length) {
						debug('%s - Adding user "%s" to roles %j of "%s:%s"', mni, currentUserId, _.map(roles, r => r.name), modelName, ctx.instance.id);
						return sec.acl.addUserRoles(currentUserId, roles);
					}
				})
				.nodeify(next);
		});
	}
};
