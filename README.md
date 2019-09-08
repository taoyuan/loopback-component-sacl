# loopback-component-sacl [![Build Status](https://travis-ci.org/taoyuan/loopback-component-sacl.svg?branch=master)](https://travis-ci.org/taoyuan/loopback-component-sacl) [![Coverage Status](https://coveralls.io/repos/github/taoyuan/loopback-component-sacl/badge.svg?branch=master)](https://coveralls.io/github/taoyuan/loopback-component-sacl?branch=master) [![Greenkeeper badge](https://badges.greenkeeper.io/taoyuan/loopback-component-sacl.svg)](https://greenkeeper.io/)

> Loopback SACL integration


## Install

```
$ npm install --save loopback-component-sacl
```

## Configuration

Example:

```json
{
	"loopback-component-sacl": {
		"ds": "db",
		"userModel": "Account",
		"rel": "store",
		"groups": ["Store"],
		"resources": {
			"Account": {
				"rel": "owner"
			},
			"Product": {
				"rowlevel": true
			}
		}
	}
}
```

Defaults:

```json
{
	"loopback-component-sacl": {
		"role": "$sacl",
		"userModel": "User",
		"modelConfig": {
			"public": false
		},
		"defaultCreatorRoles": [
		 	"member",
		 	"manager"
		],
		"defaultPermissions": {
		 	"member": "read",
		 	"manager": [
				"write",
				"manage"
		 	],
		 	"admin": "*"
		}
	}
}
```

## Usage

__Coming Soon__

## API

__Coming Soon__

## License

MIT © [Yuan Tao](https://github.com/taoyuan)
