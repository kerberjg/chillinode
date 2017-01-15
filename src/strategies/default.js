"use strict"
const passwd = require('passwd-linux');

module.exports = {
	authenticate: (body, cb) => {
		const username = body.username;
		const password = body.password;
		let user = {};

		// Authenticate
		async.waterfall([
			// Check if user exists
			(cb2) => {
				passwd.checkUser(username, (err, res) => {
					if(err) {
						console.error("There was an error while checking the existence of the user:\n" + err.stack);
						cb2(err);
					} else if(res === 'userExist')
						cb(null, { username: username });
				});
			},
			// Check user password
			(user, cb2) => {
				passwd.checkPass(user.username, password, (err, res) => {
					if(err) {
						console.error("There was an error while checking user's password:\n" + err.stack);
						cb2(err);
					} else
						cb(null, { username: username, authenticated: (res === 'passwordCorrect') });
				});
			}
		], (err, user) => {
			cb(err, user);
		});
	}
};