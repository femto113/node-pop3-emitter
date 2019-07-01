var pop3 = require('..');
var crypto = require("crypto");
var util = require('util');
var fs = require('fs');
var FakeMailStore = require('./fakemailstore.js');

mailstore = new FakeMailStore("mailboxes.json");

var numConnections = 0;
var options = {
  debug: true,
  // alternate apop support on each connection
  apop:  function () {
    numConnections++;
    apop = !!(numConnections % 2);
    console.log("connection %d: apop %s be supported", numConnections, apop ? "WILL" : "WILL NOT");
    return apop;
  },
  key:  fs.readFileSync("privkey.pem"),
  cert: fs.readFileSync("cert.pem")
};
var server = pop3.createServer('example.com', options, function (connection, callback) {
  console.log("TEST SERVER: connection from", connection.socket.remoteAddress);
  return callback(true);
});

server.on('list', function(user, which, callback) {
  mailstore.get_mailbox(user, function (err, mailbox) {
    if (err) return callback([]);
    sizes = mailbox.messages.map(m => m.size)
    if (which) {
      if (which > sizes.length) {
        sizes = []
      } else {
        sizes = [sizes[which - 1]]
      }
    }
    return callback(sizes);
  });
});

server.on('uidl', function(user, which, callback) {
  // TODO: is there supposed to be pagination or a limit of some sort?
  console.log('uidl requested for',  user);
  mailstore.get_mailbox(user, function (err, mailbox) {
    if (err) return callback([]);
    uids = mailbox.messages.map(m => m.uid);
    if (which) {
      if (which > uids.length) {
        uids = []
      } else {
        uids = [uids[which - 1]]
      }
    }
    return callback(uids);
  });
});

server.on('authenticate', function (user, hashfunc, password, callback) {
  mailstore.get_mailbox(user, function (err, mailbox) {
    if (err) return callback(false);
    hashed = hashfunc(mailbox.password)
    ok = hashed === password;
    if (!ok)
      console.log("hashfunc(%j) => %j !== %j", mailbox.password, hashed, password);
    return callback(ok);
  });
});

server.on('retrieve', function (user, which, callback) {
  mailstore.get_mailbox(user, function (err, mailbox) {
    if (err) return callback(null); // TODO: take an err param? would be more node-y
    if (which > mailbox.messages.length)
      return callback(null); // TODO: take an err param? would be more node-y
    // NOTE: which values are 1 based, messages array is 0 based
    console.log(user, which, mailbox.messages[which - 1]);
    return callback(mailbox.messages[which - 1].body);
  });
});

server.on('quit', function (user, dele, callback) {
  mailstore.get_mailbox(user, function (err, mailbox) {
    return callback(false); // TODO: take an err param? would be more node-y
    // splice out the deleted messages
    // this is done in reverse order to preserve which == index + 1 relationship
    dele.sort().reverse().forEach(which => mailbox.messages.splice(which - 1, 1));
    return callback(true);
  });
});

server.listen(110);
