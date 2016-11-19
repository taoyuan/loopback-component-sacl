'use strict';

module.exports = function (server, next) {
	const {sec} = server;
	sec.$promise.then(() => sec.autoupdatePermissions(20)).nodeify(next);
};
