"use strict";

const debug = require('debug')('loopback:component:sacl:security');
const g = require('strong-globalize')();
const assert = require('assert');
const _ = require('lodash');
const Promise = require('bluebird');
const sacl = require('sacl');
const chalk = require('chalk');
const util = require('util');
const LoopbackContext = require('loopback-context');
const utils = require('./utils');

class Security {

	constructor(app, options) {

		this.app = app;
		this.options = options = _.defaults({}, options, {
			role: '$sacl',
			userModel: 'User',
			owners: [],
			modelConfig: {
				public: false
			}
		});

		options.owners = Array.isArray(options.owners) ? options.owners : [options.owners];

		// resolve custom models
		let ds = options.dataSource || options.datasource || options.ds;
		if (typeof ds === 'string') {
			ds = app.dataSources[ds];
		}

		this.acl = sacl.acl(ds, options);

		_.forEach(this.acl.models, m => app.model(m, _.assign({dataSource: ds}, options.modelConfig)));
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


	build() {
		const {owners, rel} = this.options;
		// load owners models
		this.owners = _.map(owners, owner => this.app.registry.getModel(owner));
		// load resources models
		this.resources = _.filter(this.app.models, modelClass => {
			const r = modelClass.relations[rel];
			return r && r.type === 'belongsTo' && !this.owners.includes(modelClass)
				&& ((r.modelTo && _.includes(this.owners, r.modelTo) || r.polymorphic));
		});

		this._buildModelsSecurity(this.owners, this.resources);
	}

	_buildModelsSecurity(owners, resources) {
		const models = _.concat(owners, resources);
		_.forEach(models, model => this._normalizeModelSecurity(model));
		_.forEach(owners, owner => this._buildOwnerRoles(owner, resources));
	}

	_normalizeModelSecurity(model) {
		const {security: settings} = model.settings;
		if (!settings) return;
		model.actions = _.transform(settings.actions, normalize(model.modelName, 'actions'), {});
		model.roles = _.transform(settings.roles, normalize(model.modelName, 'roles'), {});

		function normalize(modelName, property) {
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
	}

	_buildOwnerRoles(owner, resources) {
		_.forEach(resources, resource => {
			if (resource.actions) {
				const resourceActions = _.transform(resource.actions, (result, action, key) => {
					key = _.toUpper(resource.modelName + ":" + key);
					result[key] = Object.assign({}, action, {name: key});
					return result;
				}, {});
				owner.actions = Object.assign(owner.actions || {}, resourceActions);
			}

			const permissions = _.get(resource, 'settings.security.default-permissions');
			if (!permissions) return;
			_.forEach(owner.roles, role => {
				let permits = permissions[role.name];
				if (!permits) return;
				if (!Array.isArray(permits)) permits = [permits];
				if (permits.includes('*')) {
					permits = Object.keys(resource.actions);
				}
				permits = _.map(permits, permit => _.toUpper(resource.modelName + ":" + permit));
				role.actions = _.concat(role.actions, permits);
			});
		});
	}

	loadAbilities() {
		const models = _.concat(this.owners, this.resources);
		debug('SACL LOAD PERMISSIONS - loading permissions from models: %j', _.map(models, m => m.modelName));
		const {Abilities} = this.app.acl;
		return Promise.map(models, m => {
			const modelName = m.modelName;
			const actions = _.map(m.actions, action => _.toUpper(action.name));
			return actions.length && Abilities.addActions(modelName, actions).then(ability => {
				if (ability) {
					debug('SACL LOAD PERMISSIONS - loaded actions "%s": %j', ability.resource, ability.actions);
				} else {
					debug('SACL LOAD PERMISSIONS - failed loading actions "%s": %j', modelName, actions);
				}
			});
		}).then(() => {
			debug('SACL LOAD PERMISSIONS - loaded all permissions successfully');
		});
	}

	setupFilters() {
		debug(chalk.yellow(`Setup Filters`));
		this.resources.forEach(model => {
			this._attachAccessObserver(model);
			// this._attachBeforeSaveObserver(modelName);
		});
	}

	/**
	 * Add access observer to a given model
	 *
	 * @param {String} model model class or model name to add hook to.
	 */
	_attachAccessObserver(model) {
		const Model = typeof model === 'string' ? app.registry.getModel(model) : model;
		const modelName = Model.modelName;

		if (typeof Model.observe !== 'function') {
			return;
		}

		debug('ACCESS observer - Attaching access observer to %s', modelName);
		Model.observe('access', (ctx, next) => {

			const currentUserId = _.get(this.getCurrentUser(), 'id');

			debug('ACCESS observer - Observing access for %s', modelName);

			if (!currentUserId) {
				debug('ACCESS observer - no user attached');
				return next();
			}

			// Do not filter if options.skipAccess has been set.
			if (ctx.options.skipAccess) {
				debug('ACCESS observer - skipAccess: true, no filter applied');
				return next();
			}

			this.acl.hasRoleByName(currentUserId, 'admin').then(isAdmin => {
				if (isAdmin) {
					debug(`ACCESS observer - current user is admin`);
					return next();
				}

				this._buildWhere(currentUserId, ctx.Model, ctx.query.where).then(where => {
					debug('ACCESS observer - appending to query: %j', where);

					if (where) {
						ctx.query.where = _.isEmpty(ctx.query.where) ? where : {and: [ctx.query.where, where]};
					}

					debug('ACCESS observer - Modified query for model %s: %j', modelName, ctx.query);

					next();
				});
			});
		});
	}

	// TODO 查询 Owner Model，查询资源，操作 Owner Model 和资源测试
	/**
	 * Build a where filter to restrict search results to a users group
	 *
	 * @param {String} userId UserId to build filter for.
	 * @param {Object} Model Model to build filter for,
	 * @param {Object} where Model to build filter for,
	 * @returns {Promise.<*|Object>} A where filter.
	 */
	_buildWhere(userId, Model, where) {
		where = where || {};
		let ownerType, ownerKey, relKey;
		if (this._isOwnerModel(Model)) {
			ownerType = Model.modelName;
			ownerKey = Model.getIdName();
		} else if (relKey = utils.getRelKey(Model, this.options.rel)) {
			ownerType = relKey.keyType || where[relKey.keyTypeWhere];
			ownerKey = relKey.keyId;

			// if (!resourceType) {
			// 	throw new Error(g.f('ACCESS denied: Where condition "%s" is required', relKey.keyTypeWhere));
			// }
		} else {
			throw new Error(g.f('ACCESS denied: Model %s has no relation %s to owner', Model.modelName, this.options.rel));
		}

		if (ownerType && where[ownerKey]) {
			const scope = ownerType + ':' + where[ownerKey];
			return this.acl.allowedResourcesWithScope(userId, scope, 'READ', Model.modelName).then(resources => {
				return {[Model.getIdName()]: {inq: _.map(resources, r => r.id)}};
			});
		}

		return this.acl.allowedResources(userId, 'READ', Model.modelName).then(resources => {
			return {[Model.getIdName()]: {inq: _.map(resources, r => r.id)}};
		});
	}

	setupRoleResolver() {
		const {acl, app, options} = this;
		const {role} = options;

		debug(`SACL ROLE RESOLVER - Registering for "${role}"`);
		const {registry} = app;
		const Role = registry.getModelByType('Role');

		Role.registerResolver(role, (role, context) => {

			debug('---------------------------------------------------------------------');
			debug('SACL ROLE RESOLVER - Hitting role resolver for: %s.%s', context.modelName, context.method);

			const modelName = context.modelName;
			const accessType = context.accessType;
			const method = context.method;
			const modelClass = context.model;
			const modelId = context.modelId;
			const userId = context.getUserId();
			const userObj = userId && this.options.userModel + ':' + userId;
			// const roleName = this.extractRoleName(role);
			// const GroupAccess = this.app.models[this.options.groupAccessModel];
			const remotingData = _.get(context, `remotingContext.args.data`);
			let action = this._getActionForMethod(modelClass, method, accessType);

			debug(`SACL ROLE RESOLVER - {role: ${chalk.blue(role)}, model: ${chalk.blue(modelName)}, method: ${chalk.blue(method)}, action: ${chalk.blue(action)}, userId: ${chalk.blue(userId)}, modelId: ${chalk.blue(modelId)}} with remoting data: ${util.inspect(remotingData)}`);

			// No userId is present
			if (!userId) {
				debug(`SACL ROLE RESOLVER - Denied access for anonymous user`);
				return Promise.resolve(false);
			}

			return acl.hasRoleByName(userId, 'admin').then(isAdmin => {
				if (isAdmin) {
					debug('SACL ROLE RESOLVER - User %s is allowed to perform any operation for role "admin"', userId);
					return true;
				}

				return Promise.all([
					this._getCurrentOwner(context),
					this._getTargetOwner(context)
				]).then(([current, target]) => { // (currentOwner, targetOwner)
					if (!current) {
						// Causes the access check to be bypassed (see below).
						debug(`SACL ROLE RESOLVER - Could not get owner, skipping ACL check on model ${chalk.blue(modelName)} for method ${chalk.bold(method)}`);
						return true;
					}

					// get action for owner
					if (!this._isOwnerModel(modelClass)) {
						action = _.toUpper(modelName + ':' + action);
					}

					return Promise.resolve(current.type === this.options.userModel && current.id === userId)
						.then(allowed => {
							if (!allowed) {
								debug('SACL ROLE RESOLVER - Checking %s whether has permission %s in owner %j', userId, action, current);
								return acl.isAllowed(userObj, utils.wrapOwner(current), action);
							}
						})
						.then(allowed => {
							debug('SACL ROLE RESOLVER - User %s is%s allowed in owner %j', userId, allowed ? '' : ' not', current);
							if (!allowed) return false;

							if (target && !_.isEqual(current, target)) {
								return acl.isAllowed(userObj, utils.wrapOwner(target), action).then(allowed => {
									debug('SACL ROLE RESOLVER - Attempting save into new target owner, User %s is%s allowed in target owner %j', userId, allowed ? '' : ' not', target);
									return allowed;
								});
							}
							return allowed;
						});
				}).then(allowed => {
					debug('---------------------------------------------------------------------');
					return allowed;
				});
			});
		});
	}

	_getActionForMethod(Model, method) {
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

	_isOwnerModel(modelClass) {
		if (!modelClass) return false;
		return _.find(this.options.owners, model => {
			const Model = this.app.models[model];

			return modelClass === Model ||
				modelClass.prototype instanceof Model ||
				modelClass === model;
		});
	}

	_getCurrentOwner(context) {
		const {rel} = this.options;
		const {model, modelName, modelId, method} = context;

		if (this._isOwnerModel(model)) {
			return {type: model, id: modelId};
		}

		return Promise.resolve().then(() => {
			if (modelId) {
				debug('Fetching current owner for model: %s, with id: %s, for method: %s', modelName, modelId, method);

				return model.findById(modelId, {}, {skipAccess: true}).then(inst => {
					if (inst) {
						const owner = utils.getOwner(model, rel, inst);
						debug('Determined current owner: %j, from model: %s, with id: %s, for method: %s', owner, modelName, modelId, method);
						return owner
					}
				});
			}
		}).then(owner => {
			if (owner) return owner;
			if (owner = utils.getOwner(model, rel, _.get(context, 'remotingContext.args.data'))) {
				debug('Determined current owner: %j, from remoting incoming data for model %s, for method %s', owner, modelName, method);
				return owner;
			}
		});
	}

	_getTargetOwner(context) {
		const {rel} = this.options;
		const {model, modelName, method} = context;
		const owner = utils.getOwner(model, rel, _.get(context, 'remotingContext.args.data'));
		if (owner) {
			debug('Determined target owner: %j, from incoming data for model: %s, for method: %s', owner, modelName, method);
		}
		return owner;
	}
}

module.exports = Security;

