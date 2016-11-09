"use strict";

const _ = require('lodash');

exports.getRelKey = function (Model, rel) {
	const relation = Model.relations[rel];

	if (!relation) return;

	if (relation.polymorphic) {
		const {discriminator, foreignKey} = relation.polymorphic;
		return {
			keyId: foreignKey,
			keyTypeWhere: discriminator
		};
	} else {
		return {
			keyType: relation.modelTo && relation.modelTo.modelName,
			keyId: relation.keyFrom
		}
	}
};

exports.getOwner = function (Model, rel, data) {
	if (!data) return;

	const relation = Model.relations[rel];

	if (!relation) return;

	let type, id;

	if (relation.polymorphic) {
		const {discriminator, foreignKey} = relation.polymorphic;
		type = data[discriminator];
		id = data[foreignKey];

		if (!type && data[rel]) {
			if (typeof data[rel] === 'string') {
				const parts = _.split(data[rel], ':');
				type = parts[0];
				id = parts[1];
			} else if (typeof data[rel] === 'object') {
				type = data[rel].type;
				id = data[rel].id;
			}
		}
	} else {
		type = relation.modelTo && relation.modelTo.modelName;
		id = data[relation.keyFrom];
	}

	if (!type) return;

	return {type, id};
};

exports.wrapOwner = function (owner) {
	if (owner && owner.type) {
		return owner.type + (_.isNil(owner.id) ? '' : ':' + owner.id);
	}
};

exports.unwrapOwner = function (data) {
	const parts = _.split(data, ':');
	return {type: parts[0], id: parts[1]};
};
