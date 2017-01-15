"use strict"
// Config
global.config = require('./config.json');
const port = process.env.PORT || global.config.port || 3000;

// Express dependencies
const express = require('express');
const bodyParser = require('body-parser');

// Express setup
const app = express();
//app.enable('trust proxy');
app.use(express.static(__dirname + '/res/static/'));
app.use(express.static(__dirname + '/node_modules/bootstrap/dist/'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.set('views', './src/views');
app.set('view engine', 'html');
app.engine('html', require('hogan-express'));

// Other dependencies
const arp = require('node-arp');

// Internal modules
const strategy = require('./src/strategies/default');
const firewall = require('./src/firewall');


/*
 *	Routes
 */

// Login page
app.get('/', (req, res) => {
	res.render('index', { unauthorized: (req.query.error == 403) });
});

// Login action
app.post('/', (req, res) => {
	async.waterfall([
		// Auth user
		(cb) => {
			strategy.authenticate(req.body, (err, user) => {
				if(err) {
					cb(err);
				} else if(user && user.authenticated)
					cb(null, user);
				else {
					cb({ status: 403 });
				}
			})
		},
		// Get MAC address
		(user, cb) => {
			user.ip = req.ip;

			arp.getMAC(req.ip, (err, mac) => {
				if(err) {
					console.error("There was an error while getting user's MAC address:\n" + err.stack);
					cb(err);
				} else if(mac) {
					user.mac = mac;
					cb(null, user);
				} else
					cb(new Error("A MAC address for user's IP wasn't found in system's ARP table"));
			});
		},
		// Add user to firewall rules
		(user, cb) => {
			firewall.authorize(mac, (err) => {
				if(err) {
					console.error("There was an error while adding user's MAC address to authorized addresses:\n" + err.stack);
					cb(err);
				} else
					cb(null, user);
			});
		}
	], (err, data) => {
		if(err) {
			if(err instanceof Error)
				res.json(err).sendStatus(500);
			else {
				res.json(err);
				switch(err.status) {
					case 403:
						return res.redirect('/?error=403');
					default:
						res.status(500);
						break;
				}

				res.end();
			}
		} else
			res.redirect(req.body.redirect);
	});
});

app.listen(port, () => {
	console.log('Setting firewall rules...');
	firewall.init((err) => {
		if(err) {
			console.error("Error initializing the firewall:\n" + err.stack);
			process.exit(-1);
		} else
			console.log(`Chillinode is now listening on port ${port}`);
	});
});