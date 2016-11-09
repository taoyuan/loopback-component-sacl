"use strict";

module.exports = function (app) {
	function inject(ctx, next) {
		const options = hasOptions(ctx.method.accepts) && (ctx.args.options || {});
		if(options) {
			options.remctx = ctx;
			options.accessToken = ctx.req.accessToken;
			options.userId = ctx.req.accessToken && ctx.req.accessToken.userId;
			ctx.args.options = options;
		}
		next();
	}
	function hasOptions(accepts) {
		for (let i = 0; i < accepts.length; i++) {
			const argDesc = accepts[i];
			if (argDesc.arg === 'options' && argDesc.injectCtx) {
				return true;
			}
		}
	}

	if(!process.env.GENERATING_SDK) {
		app.remotes().before('*.*', inject);

		app.remotes().before('*.prototype.*', function(ctx, instance, next) {
			if (typeof instance === 'function') {
				next = instance;
			}
			inject(ctx, next);
		});

		const blacklist = ['login', 'logout', 'confirm', 'resetPassword'];

		// unfortunately this requires us to add the options object
		// to the remote method definition
		app.remotes().methods().forEach(function(method) {
			if(!hasOptions(method.accepts) && blacklist.indexOf(method.name) === -1) {
				method.accepts.push({
					arg: 'options',
					description: '**Do not implement in clients**',
					type: 'object',
					injectCtx: true,
					http: () => ({})
				});
			}
		});
	}
};
