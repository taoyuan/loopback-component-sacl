"use strict";

const debug = require('debug')('loopback:component:sacl:security');
const g = require('strong-globalize')();
const assert = require('assert');
const _ = require('lodash');
const sacl = require('sacl');
const util = require('util');
const LoopbackContext = require('loopback-context');
const Promise = require('bluebird');
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
			}
		});

		options.groupModels = Array.isArray(options.groupModels) ? options.groupModels : [options.groupModels];

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

	allowDefaultPermissions(instance) {
		const relname = this.options.rel;
		assert(instance, g.f('"resource" is required'));

		const Model = instance.constructor;
		const modelName = Model.modelName;
		const ss = Model.security;
		const isGroupModel = this.isGroupModel(instance.constructor);

		let promise, rolesNames;
		if (isGroupModel) {
			rolesNames = Object.keys(ss.roles);
			promise = Promise.resolve(instance);
		} else {
			assert(typeof instance[relname] === 'function', g.f('resource has no relation %s', relname));
			rolesNames = Object.keys(ss.permissions);
			promise = Promise.fromCallback(cb => instance[relname](cb));
		}

		return promise.then(group => {
			return this.acl.Role.findByScope(group, {where: {name: {inq: rolesNames}}}).then(roles => {
				const groupModelName = group.constructor.modelName;
				const groupId = group.id;
				if (!roles.length) {
					debug('allowDefaultPermissions - No roles %j found for %s:%s', rolesNames, groupModelName, groupId);
				}
				return Promise.each(roles, role => {
					let actions = _.map(isGroupModel ? ss.roles[role.name].actions : ss.permissions[role.name], _.toUpper);
					debug('allowDefaultPermissions - Allowing %s:%s:%s to access %s:%s with permissions %j', groupModelName, groupId, role.name, modelName, instance.id, actions);
					return this.acl.allow(role, instance, actions);
				});
			});
		}).thenReturn();
	}

}

module.exports = Security;

