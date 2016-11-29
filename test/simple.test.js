"use strict";

const assert = require('chai').assert;
const s = require('./support');
const app = require('./fixtures/app/server/server');

describe('basic', () => {

	it('should work', () => {

		assert.ok(app);
	});
});
