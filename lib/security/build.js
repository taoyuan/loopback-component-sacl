"use strict";

const debug = require('debug')('loopback:component:sacl:build');
const g = require('strong-globalize')();
const _ = require('lodash');
const deprecated = require('depd')('loopback:component:sacl:build');
const utils = require('../utils');

module.exports = function (sec) {

	const {groups, resources} = sec;

	debug('build models security for group models %j and resource models %j',
		utils.toModelsNames(groups), utils.toModelsNames(resources));

	const models = _.concat(groups, resources);
	_.forEach(models, model => transform(model));
	_.forEach(groups, group => buildGroupRoles(group, resources));

	// ----------------------------------------------------------------
	//  Internal Functions
	// ----------------------------------------------------------------

	function transform(model) {
		const securitySettings = model.settings.security || {};
		const security = model.security = model.security || {};
		if (_.has(securitySettings, 'actions')) {
			security.actions = _.transform(securitySettings.actions, normalizer(model.modelName, 'actions'), {});
		}
		if (_.has(securitySettings, 'roles')) {
			security.roles = _.transform(securitySettings.roles, normalizer(model.modelName, 'roles'), {});
		}
		if (_.has(securitySettings, 'permissions')) {
			security.permissions = securitySettings.permissions;
		}
		if (_.has(securitySettings, 'default-permissions')) {
			deprecated('"default-permissions" has been deprecated, using "permissions" instead');
			security.permissions = securitySettings['default-permissions'];
		}
		if (!sec.isGroupModel(model)) {
			security.permissions = security.permissions || sec.options.defaultPermissions;
			security.permissions = _.transform(security.permissions, (result, v, k) => result[k] = utils.sureArray(v), {});
		}
	}

	function buildGroupRoles(group, resources) {
		const groupSecurity = group.security;
		_.forEach(resources, resource => {
			const resourceSecurity = resource.security;
			if (resourceSecurity.actions) {
				const resourceActions = _.transform(resourceSecurity.actions, (result, action, key) => {
					key = _.toUpper(resource.modelName + ":" + key);
					result[key] = Object.assign({}, action, {name: key});
					return result;
				}, {});
				groupSecurity.actions = Object.assign(groupSecurity.actions || {}, resourceActions);
			}

			if (!resourceSecurity.permissions) return;

			_.forEach(group.roles, role => {
				let permittedActions = resourceSecurity.permissions[role.name];
				if (!permittedActions) return;
				if (permittedActions.includes('*')) {
					permittedActions = Object.keys(resource.actions);
				}
				permittedActions = _.map(permittedActions, permit => _.toUpper(resource.modelName + ":" + permit));
				role.actions = _.concat(role.actions, permittedActions);
			});
		});
	}
};

function normalizer(modelName, property) {
	return (result, val, key) => {
		if (typeof val === 'string') {
			val = {title: val}
		}
		if (typeof val !== 'object') {
			throw new Error(g.f('Invalid settings for model %s security settings %s.%s', modelName, property, key));
		}
		val.name = key;
		result[key] = val;
		return result;
	}
}
