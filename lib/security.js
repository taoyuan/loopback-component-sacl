"use strict";

const debug = require('debug')('loopback:component:sacl:security');
const g = require('strong-globalize')();
const _ = require('lodash');
const assert = require('assert');
const sacl = require('sacl');
const util = require('util');
const LoopbackContext = require('loopback-context');
const Promise = require('bluebird');
const chalk = require('chalk');
const utils = require('./utils');

class Security {

	constructor(app, options) {

		this.app = app;
		this.options = options = _.defaults({}, options, {
			role: '$sacl',
			userModel: 'User',
			groupModels: [],
			rel: 'owner',
			modelConfig: {
				public: false
			},
			defaultCreatorRoles: ['member', 'manager'],
			defaultPermissions: {
				"member": "read",
				"manager": ["write", "manage"],
				"admin": "*"
			}
		});

		options.groupModels = Array.isArray(options.groupModels) ? options.groupModels : [options.groupModels];
		options.defaultCreatorRoles = utils.sureArray(options.defaultCreatorRoles);

		// resolve custom models
		let ds = options.dataSource || options.datasource || options.ds;
		if (typeof ds === 'string') {
			ds = app.dataSources[ds];
		}

		this.acl = sacl.acl(ds, options);

		_.forEach(this.acl.models, m => app.model(m, _.assign({dataSource: ds}, options.modelConfig)));


		const {groupModels, rel} = this.options;

		// load groups models
		this.groups = _.map(groupModels, owner => this.app.registry.getModel(owner));

		// load resources models
		this.resources = _.filter(this.app.models, modelClass => {
			const r = modelClass.relations[rel];
			return r && r.type === 'belongsTo' && !this.groups.includes(modelClass)
				&& ((r.modelTo && _.includes(this.groups, r.modelTo) || r.polymorphic));
		});
	}

	/**
	 * Get the currently logged in user.
	 *
	 * @returns {Object} Returns the currently logged in user.
	 */
	getCurrentUser() {
		const ctx = LoopbackContext.getCurrentContext();
		return ctx && ctx.get('currentUser') || null;
	}

	getCurrentUserId() {
		return _.get(this.getCurrentUser(), 'id');
	}

	getActionForMethod(Model, method) {
		if (typeof method === 'string') {
			method = {name: method};
		}

		assert(typeof method === 'object', 'method is a required argument and must be a RemoteMethod object');

		const action = _.find(Model.actions, action => _.includes(action.methods, method));
		if (action) return action.name;

		switch (method.name) {
			case'create':
				return sacl.MANAGE;
			case 'updateOrCreate':
				return sacl.WRITE;
			case 'upsertWithWhere':
				return sacl.WRITE;
			case 'upsert':
				return sacl.WRITE;
			case 'exists':
				return sacl.READ;
			case 'findById':
				return sacl.READ;
			case 'find':
				return sacl.READ;
			case 'findOne':
				return sacl.READ;
			case 'destroyById':
				return sacl.MANAGE;
			case 'deleteById':
				return sacl.MANAGE;
			case 'removeById':
				return sacl.MANAGE;
			case 'count':
				return sacl.READ;
			default:
				return sacl.MANAGE;
		}
	}

	isGroupModel(modelClass) {
		if (!modelClass) return false;
		return _.find(this.options.groupModels, model => {
			const Model = this.app.models[model];

			return modelClass === Model ||
				modelClass.prototype instanceof Model ||
				modelClass === model;
		});
	}

	allowDefaultPermissions(inst) {
		const rel = this.options.rel;
		assert(inst, g.f('"inst" is required'));

		const Model = inst.constructor;
		const modelName = Model.modelName;
		const ss = Model.security;
		const isGroupModel = this.isGroupModel(inst.constructor);

		let promise, rolesNames;
		if (isGroupModel) {
			rolesNames = Object.keys(ss.roles);
			promise = Promise.resolve(inst);
		} else {
			assert(typeof inst[rel] === 'function', g.f('resource has no relation %s', rel));
			rolesNames = Object.keys(ss.permissions);
			promise = Promise.fromCallback(cb => inst[rel]({}, {skipAccess: true}, cb)).catch(err => {
				if (/Polymorphic model not found/.test(err.message)) {
					return;
				}
				throw err;
			});
		}

		return promise.then(group => {
			if (!group) {
				return debug('allowDefaultPermissions - Skip for no group instance found for %s:%s', modelName, inst.id);
			}
			return this.acl.Role.findByScope(group, {where: {name: {inq: rolesNames}}}).then(roles => {
				const groupModelName = group.constructor.modelName;
				const groupId = group.id;
				if (!roles.length) {
					debug('allowDefaultPermissions - No roles %j found for %s:%s', rolesNames, groupModelName, groupId);
				}
				return Promise.each(roles, role => {
					let actions = _.map(isGroupModel ? ss.roles[role.name].actions : ss.permissions[role.name], _.toUpper);
					debug('allowDefaultPermissions - Allowing %s:%s:%s to access %s:%s with permissions %j', groupModelName, groupId, role.name, modelName, inst.id, actions);
					return this.acl.allow(role, inst, actions);
				});
			});
		}).thenReturn();
	}

	assignRolesForGroupCreator(inst, userId) {
		const {options, acl} = this;
		const Model = inst.constructor;
		const modelName = Model.modelName;
		const roles = Object.keys(Model.security.roles);
		debug('assignRolesForGroupCreator - Sure group %s:%s with roles %j', modelName, inst.id, roles);
		return Promise.map(roles, role => acl.Role.sure(role, inst)).then(roles => {
			if (userId === null) return;
			userId = userId || inst.userId || inst.owner;
			let promise;
			if (typeof userId === 'function') {
				// Try to follow belongsTo
				const rel = _.find(Model.relations, rel => rel.type === 'belongsTo' && isUserClass(rel.modelTo));
				if (!rel) return;
				promise = Promise.fromCallback(cb => inst[rel.name](cb));
			} else {
				promise = Promise.resolve(userId);
			}

			return promise.then(userId => {
				if (!userId) {
					debug('assignRolesForGroupCreator - No user or creator of group %s:%s found, skip assign roles for creator.', modelName, inst.id);
					return;
				}
				return Promise.filter(roles, role => options.defaultCreatorRoles.includes(role.name)).then(roles => {
					debug('assignRolesForGroupCreator - Assign user %s to roles %j', userId, _.map(roles, r => r.name));
					return acl.addUserRoles(userId, roles);
				});
			})
		})
	}

	autoupdateGroupsPermissions(pageSize) {
		debug('Auto updating groups permissions');
		const {acl} = this;

		const updateOne = (inst) => {
			const Model = inst.constructor;
			const roles = Object.keys(Model.security.roles);
			return Promise.map(roles, role => acl.Role.sure(role, inst))
				.then(this.assignRolesForGroupCreator(inst))
				.then(this.allowDefaultPermissions(inst));
		};

		function update(Model, limit, offset) {
			if (_.isEmpty(Model.security.roles)) {
				return debug('Skip %s auto update permissions for no default roles defined for it', Model.modelName);
			}
			offset = offset || 0;
			const filter = limit ? {limit, offset} : null;
			return Promise.resolve(Model.find(filter, {skipAccess: true})).then(instances => {
				if (_.isEmpty(instances)) return;
				return Promise.map(instances, updateOne).then(() => {
					if (!filter || instances.length < limit) return;
					return update(Model, limit, limit + offset)
				});
			});
		}

		return Promise.each(this.groups, model => update(model, pageSize));
	}

	autoupdateResourcesPermissions(pageSize) {
		debug('Auto updating resources permissions');
		const updateOne = (inst) => this.allowDefaultPermissions(inst);

		function update(Model, limit, offset) {
			offset = offset || 0;
			const filter = limit ? {limit, offset} : null;
			return Promise.resolve(Model.find(filter, {skipAccess: true})).then(instances => {
				if (_.isEmpty(instances)) return;
				return Promise.map(instances, updateOne).then(() => {
					if (!filter || instances.length < limit) return;
					return update(Model, limit, limit + offset)
				});
			});
		}

		return Promise.each(this.resources, model => update(model, pageSize));
	}

	autoupdatePermissions(pageSize) {
		debug('---------------------------------------------------------------');
		debug('Auto updating permissions %s.', pageSize ? 'with page size ' + chalk.blue(pageSize) : '');
		debug('---------------------------------------------------------------');
		return Promise.each([
			() => this.autoupdateGroupsPermissions(pageSize),
			() => this.autoupdateResourcesPermissions(pageSize)
		], fn => fn()).then(() => {
			debug('---------------------------------------------------------------');
		});
	}
}

module.exports = Security;

function isUserClass(modelClass) {
	if (!modelClass) return false;
	const User = modelClass.modelBuilder.models.User;
	if (!User) return false;
	return modelClass == User || modelClass.prototype instanceof User;
}
