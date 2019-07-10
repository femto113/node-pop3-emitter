const fs = require('fs'),
    util = require('util'),
  crypto = require('crypto');

// a simple fake mailstore to help build out our test server
function FakeMailStore(filename) {
  this.mailboxes = JSON.parse(fs.readFileSync(filename));

  this.addresses = Object.keys(this.mailboxes).sort();
  // generate some messages for each mailbox (except the empty one)
  this.addresses.filter(a => !a.startsWith("empty")).forEach(function (address, mbno) {
    message_count = 3 * (mbno + 1);
    for (var index = 1; index <= message_count; index++) {
      subject = util.format("Message %d of %d", index, message_count);
      lines = []
      line_count = (mbno + 1) % 4 + 2;
      for (var line = 1; line <= line_count; line++)
        lines.push(util.format("This is line %d of %d of the body of message %d.", line, line_count, index));
      body = lines.join('\n');
      message = this.make_message(index, "sender@example.org", address, subject, body);
      this.mailboxes[address].messages.push(message);
    }
  }.bind(this));
}

FakeMailStore.prototype.make_message = function (index, from, to, subject, body) {
  d = new Date('2019-06-01');
  d.setHours(index % 24, index % 60, index % 60, index % 1000);
  message = {
    headers: [
      "Date: " + d.toString(),
      "From: " + from,
      "To: " + to, 
      "Subject: " + subject
    ],
    body: body
  }
  // this should match the size of the message as sent in a POP3 retrieve command
  message.size = message.headers.concat('').concat(message.body).concat('').join('\r\n').length
  // Per RFC 1939
  // The unique-id of a message is an arbitrary server-determined
  // string, consisting of one to 70 characters in the range 0x21
  // to 0x7E, which uniquely identifies a message within a
  // maildrop and which persists across sessions. [...]
  // While it is generally preferable for server implementations
  // to store arbitrarily assigned unique-ids in the maildrop,
  // this specification is intended to permit unique-ids to be
  // calculated as a hash of the message.
  message.uid = crypto.createHash('md5').update(message.body).digest().toString("hex");
  return message;
};

// this is async just for effect, imagine fetching from redis or similar
FakeMailStore.prototype.get_mailbox = function (user, callback) {
  // TODO: append @example.com if not alredy in user
  if (!(user in this.mailboxes))
    return setImmediate(() => callback("unknown user " + user));
  return setImmediate(() => callback(null, this.mailboxes[user]));
};

module.exports = FakeMailStore;
