"use strict";

const debug = require('debug')('loopback:component:sacl:security');
const g = require('strong-globalize')();
const assert = require('assert');
const _ = require('lodash');
const Promise = require('bluebird');
const sacl = require('sacl');
const chalk = require('chalk');
const util = require('util');
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

		// resolve custom models
		let ds = options.dataSource || options.datasource || options.ds;
		if (typeof ds === 'string') {
			ds = app.dataSources[ds];
		}

		this.acl = sacl.acl(ds, options);

		_.forEach(this.acl.models, m => app.model(m, _.assign({dataSource: ds}, options.modelConfig)));
	}

	loadAbilities() {
		const models = _.filter(this.app.models, m => _.has(m, 'settings.security.permissions'));
		if (!models.length) {
			return Promise.resolve();
		}
		debug('SACL LOAD PERMISSIONS - loading permissions from models: %j', _.map(models, m => m.modelName));
		const {Abilities} = this.app.acl;
		return Promise.map(models, m => {
			let actions = _.get(m, 'settings.security.actions') || [];
			const permissions = _.get(m, 'settings.security.permissions');
			actions = actions.concat(_(permissions).map(p => p.action).filter(action => !!action));
			actions = _(actions).map(_.toUpper).uniq().value();

			return Abilities.addActions(m.modelName, actions).then(() => {
				debug('SACL LOAD PERMISSIONS - loaded actions "%s": %j', m.modelName, actions);
			});
		}).then(() => {
			debug('SACL LOAD PERMISSIONS - loaded all permissions successfully');
		});
	}

	loadDefaultRoles() {

	}

	setupFilters() {
		debug(chalk.yellow(`Setup Filters`));
		const models = this._getResourceModels();

		models.forEach(modelName => {
			this._attachAccessObserver(modelName);
			// this._attachBeforeSaveObserver(modelName);
		});
	}

	_isReservedModel(modelClass) {
		if (!modelClass) return false;
		const models = _.values(this.acl.models).concat(['AccessToken']);
		return _.find(models, model => {
			const Model = typeof model === 'string' ? this.app.models[model] : model;

			return modelClass === Model
				|| modelClass.prototype instanceof Model
				|| modelClass === model;
		});
	}

	/**
	 * Get a list of resource models (models that have a belongs to relationship to the owner model)
	 *
	 * @returns {Array} Returns a list of resource models.
	 */
	_getResourceModels() {
		if (!this.options.resourceModels || !Array.isArray(this.options.resourceModels)) {
			this.options.resourceModels = [];
		}

		if (this.options.resourceModels.length) {
			return this.options.resourceModels;
		}

		const models = this.options.resourceModels;

		_.forEach(this.options.owners, owner => {
			owner = this.app.models[owner];
			!models.includes(owner.modelName) && models.push(owner.modelName);
			_.forEach(owner.relations, rel => {
				if (rel.type === 'hasMany' && !this._isReservedModel(rel.modelTo)) {
					!models.includes(rel.modelTo.modelName) && models.push(rel.modelTo.modelName);
				}
			});
		});

		debug('Got group content models: %j', models);
		return models;
	}

	/**
	 * Add access observer to a given model
	 *
	 * @param {String} modelName name to add hook to.
	 */
	_attachAccessObserver(modelName) {
		const Model = this.app.models[modelName];
		const _modelName = modelName;

		if (typeof Model.observe !== 'function') {
			return;
		}

		debug('ACCESS observer - Attaching access observer to %s', _modelName);
		Model.observe('access', (ctx, next) => {

			const {options} = ctx;
			const currentUserId = options && options.userId;

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

					debug('ACCESS observer - Modified query for model %s: %j', _modelName, ctx.query);

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

		const security = _.get(Model, 'settings.security');
		if (security) {
			const permissions = security.permissions;
			const permission = _.find(permissions, p => p.methods && (p.methods === method.name || _.includes(p.methods, method.name)));
			if (permission && permission.action) {
				return permissions.action;
			}
		}

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
				return sacl.EXECUTE;
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

