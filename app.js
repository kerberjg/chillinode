"use strict"
// Config
global.config = require('./config.json');
const port = process.env.PORT || global.config.port || 3000;

// Express dependencies
const express = require('express');
const bodyParser = require('body-parser');

// Express setup
const app = express();
app.enable('trust proxy');
app.use(express.static('../res/static'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

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
	res.render('login', { unauthorized: (req.query.error == 403) });
});

// Login action
app.post('/', (req, res) => {
	let user = strategy.checkCredentials(req.body);

	if(user)
		arp.getMAC(req.ip, (err, mac) => {
			if(err)
				res.json(err).sendStatus(500);
			else if(mac)
				firewall.authorize(mac, (err) => {
					if(err)
						res.json(err).sendStatus(500);
					else
						res.redirect(req.body.redirect);
				});
			else
				res.sendStatus(404);
		});
	else
		res.redirect('/?error=403');
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