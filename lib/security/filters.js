"use strict";

const debug = require('debug')('loopback:component:sacl:filters');
const g = require('strong-globalize')();
const _ = require('lodash');
const chalk = require('chalk');
const utils = require('../utils');

module.exports = function (sec) {
	debug(chalk.yellow('Setup Filters Observer'));

	const {app} = sec;
	const models = sec.models;

	models.filter(m => !m._acopts || m._acopts.rowlevel).forEach(model => {
		attachAccessObserver(model);
	});

	// ----------------------------------------------------------------
	//  Internal Functions
	// ----------------------------------------------------------------
	/**
	 * Add access observer to a given model
	 *
	 * @param {String} model model class or model name to add hook to.
	 */
	function attachAccessObserver(model) {
		const Model = app.registry.getModel(model);

		if (typeof Model.observe !== 'function') return;

		debug('ACCESS observer - Attaching access observer to %s', Model.modelName);

		const modelName = Model.modelName;
		const mni = chalk.blue(modelName);

		Model.observe('access', (ctx, next) => {
			// Do not filter if options.skipAccess has been set.
			if (ctx.options.skipAccess) {
				debug('%s - Skip filter for options skipAccess has been set as true', mni);
				return next();
			}

			const currentUserId = sec.getCurrentUserId();

			debug('%s - Observing access for %s', mni, modelName);

			if (!currentUserId) {
				debug('%s - Skip filter for no user attached', mni);
				return next();
			}

			sec.acl.hasRoleByName(currentUserId, 'admin').then(isAdmin => {
				if (isAdmin) {
					debug('%s - Skip filter for current user is admin', mni);
					return next();
				}

				buildWhere(currentUserId, ctx.Model, ctx.query.where).then(where => {
					debug('%s - Appending to query: %j', mni, where);

					if (where) {
						ctx.query.where = _.isEmpty(ctx.query.where) ? where : {and: [ctx.query.where, where]};
					}

					debug('%s - Modified query for model %s: %j', mni, modelName, ctx.query);

					next();
				});
			});
		});
	}

	/**
	 * Build a where filter to restrict search results to a users group
	 *
	 * @param {String} userId UserId to build filter for.
	 * @param {Object} Model Model to build filter for,
	 * @param {Object} where Model to build filter for,
	 * @returns {Promise.<*|Object>} A where filter.
	 */
	function buildWhere(userId, Model, where) {
		const rel = sec.relname(Model);
		where = where || {};
		let groupType, groupKey, relKey;
		if (sec.isGroupModel(Model)) {
			groupType = Model.modelName;
			groupKey = Model.getIdName();
		} else if (relKey = utils.getRelKey(Model, rel)) {
			groupType = relKey.keyType || where[relKey.keyTypeWhere];
			groupKey = relKey.keyId;
		} else {
			throw new Error(g.f('ACCESS denied: Model %s has no relation %s to group', Model.modelName, rel));
		}

		const mni = chalk.blue(Model.modelName);
		debug('%s - Group Type: %s, Group Key: %s, Where: %j', mni, groupType, groupKey, where);

		if (groupType && where[groupKey]) {
			const scope = {type: groupType, id: where[groupKey]};
			debug('%s - Find allowed resources with scope %j', mni, scope);
			return sec.acl.allowedResourcesWithScope(userId, scope, 'READ', Model.modelName).then(resources => {
				return {[Model.getIdName()]: {inq: _.map(resources, r => r.id)}};
			});
		}

		debug('%s - Find allowed resources for model %s', mni, Model.modelName);
		return sec.acl.allowedResources(userId, 'READ', Model.modelName).then(resources => {
			return {[Model.getIdName()]: {inq: _.map(resources, r => r.id)}};
		});
	}

};
