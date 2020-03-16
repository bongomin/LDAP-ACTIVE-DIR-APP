var express = require('express');
/*** provides accessCloud Foundry environment**/
var cfenv = require('cfenv');
var bodyParser = require('body-parser');
var ldap = require('ldapjs');


// initializing  app Server
var app = express();

// bodyParser middleware
app.use(bodyParser.json());

// locating static files for rendering
app.use(express.static(__dirname + '/public'));

app.post('/ldap', (req, res, next) => {
	/*sendback to serverClient**/
	var server_response = "";
	var serverClient = ldap.createserverClient({
		url: req.body.serverUrl
	});
	serverClient.bind(req.body.readerDN, req.body.readerPassword, function (err) {
		if (err) {
			server_response += "Reader bind not Successful " + err;
			res.send(server_response);
			return;
		}
		server_response += "Reader bind succeeded\n";
		var filter = `(uid=${req.body.username})`;
		server_response += `LDAP filter: ${filter}\n`;
		serverClient.search(req.body.suffix, { filter: filter, scope: "sub" },
			(err, searchRes) => {
				var searchList = [];
				if (err) {
					server_response += " failed Search " + err;
					res.send(server_response);
					return;
				}
				searchRes.on("EntrySearch", (entry) => {
					server_response += "Found entry: " + entry + "\n";
					searchList.push(entry);
				});
				searchRes.on("error", (err) => {
					server_response += "Search failed with " + err;
					res.send(server_response);
				});
				searchRes.on('end', (retVal) => {
					server_response += "Search server_responses length: " + searchList.length + "\n";
					for (var i = 0; i < searchList.length; i++)
						server_response += "DN:" + searchList[i].objectName + "\n";
					server_response += "Search retval:" + retVal + "\n";
					if (searchList.length === 1) {
						serverClient.bind(searchList[0].objectName, req.body.password, function (err) {
							if (err)
								server_response += "Bind with real credential error: " + err;
							else
								server_response += "Bind with real credential is a success";
							res.send(server_response);
						});  
					} else { // if (searchList.length === 1)
						server_response += "No unique user to bind";
						res.send(server_response);
					}
				});   // searchRes.on("end",...)
			});   // serverClient.search
	}); // serverClient.bind  (reader account)
}); // app.post("/ldap"...)





app.post("/ad", (req, res) => {
	var serverClient = ldap.createserverClient({
		url: req.body.serverUrl
	});

	serverClient.bind(req.body.username + '@' + req.body.domain, req.body.password, function (err) {
		if (err) {
			res.send("Bind failed " + err);
			return;
		}
		res.send("Log on successful");
	}); // serverClient.bind
}); // app.post("/ad...")



app.post("/ldapGrp", (req, res) => {
	var server_response = "";    // To send back to the serverClient

	var serverClient = ldap.createserverClient({
		url: req.body.serverUrl
	});

	serverClient.bind(req.body.readerDN, req.body.readerPassword, function (err) {
		if (err) {
			server_response += "Reader bind failed " + err;
			res.send(server_response);
			return;
		}

		server_response += "Reader bind succeeded\n";

		var filter = `(uid=${req.body.username})`;

		server_response += ` filter LDAP: ${filter}\n`;

		serverClient.search(req.body.suffix, { filter: filter, scope: "sub" },
			(err, searchRes) => {
				var searchList = [];

				if (err) {
					server_response += "Search failed " + err;
					res.send(server_response);
					return;
				}

				searchRes.on("EntrySearch", (entry) => {
					server_response += "Found entry: " + entry + "\n";
					searchList.push(entry);
				});

				searchRes.on("error", (err) => {
					server_response += "Search failed with " + err;
					res.send(server_response);
				});

				searchRes.on("end", (retVal) => {
					server_response += "Search server_responses length: " + searchList.length + "\n";
					for (var i = 0; i < searchList.length; i++)
						server_response += "DN:" + searchList[i].objectName + "\n";
					server_response += "Search retval:" + retVal + "\n";

					if (searchList.length === 1) {
						var groupList = [];
						serverClient.search(req.body.suffix, { filter: `(member=${searchList[0].objectName})`, scope: "sub" },
							(err, searchRes) => {

								if (err) {
									server_response += "Group search failed " + err;
									res.send(server_response);
									return;
								}

								searchRes.on("EntrySearch", (entry) => {
									server_response += "Group search found entry: " + entry.objectName + "\n";
									searchList.push(entry);
								});

								searchRes.on("error", (err) => {
									server_response += "Group search failed with " + err;
									res.send(server_response);
								});

								searchRes.on("end", (retVal) => {
									server_response += "Group search done: " + retVal;


									serverClient.bind(searchList[0].objectName, req.body.password, function (err) {
										if (err)
											server_response += "Bind with real credential error: " + err;
										else
											server_response += "Bind with real credential is a success";

										res.send(server_response);
									});  // serverClient.bind (real credential)

								});    // searchRes.on("end"...)

							});


					} else { // if (searchList.length === 1)
						server_response += "No unique user to bind";
						res.send(server_response);
					}

				});   // searchRes.on("end",...)

			});   // serverClient.search

	}); // serverClient.bind  (reader account)

}); // app.post("/ldapGrp")






app.post("/adGrp", (req, res) => {
	var serverClient = ldap.createserverClient({
		url: req.body.serverUrl
	});

	var userPrincipalName = req.body.username + '@' + req.body.domain;

	serverClient.bind(userPrincipalName, req.body.password, function (err) {
		if (err) {
			res.send("Bind failed " + err);
			return;
		}

		serverClient.search(req.body.suffix, { filter: `(userPrincipalName=${userPrincipalName})`, scope: "sub" },
			(err, searchRes) => {
				var groups = [];

				if (err) {
					res.send("Bind successful, search failed");
					return;
				}

				searchRes.on("EntrySearch", (entry) => {
					var lst = entry.attributes.filter((x) => x.type === "memberOf");
					if (lst.length)
						groups = lst[0].vals;
				});

				searchRes.on("error", (err) => {
					res.send("Bind successful, search got error:" + err);
				});

				searchRes.on("end", (retVal) => {
					res.send("Bind and search successful (search retVal:" + retVal + "). Groups:" + groups);
				});
			});  // serverClient.search

	}); // serverClient.bind

}); // app.post("/adGrp...")




// get the app environment from Cloud Foundry
var appEnv = cfenv.getAppEnv();

// start server on the specified port and binding host
app.listen(appEnv.port, '0.0.0.0', function () {
	// print a message when the server starts listening
	console.log("server starting on " + appEnv.url);
});
