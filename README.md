# pop3-emitter

## Motivation

This repository is a companion to [node-smtp-receiver](/femto113/node-smtp-receiver),
and shares a similar design.  Together they provide a the ability to implement a
simple mail server capable of receiving messages from other servers via SMTP and
retrieving those message via POP3.

As with the companion module, the design goals here are minimalist:

- sufficiently complete coverage of POP3 to allow retrieving mail with common clients and libraries
- event oriented (so listeners, not callbacks or promises)
- no dependencies
- low resource requirements (so can run in any context)
- easy to configure and extend

NOTE: This module only implements the protocol layer, it delegates authentication and maildrop
management to the parent application by emitting events.

## Basic Usage

Similar to node's `HTTPSever`, you call `createServer` to create a `POP3Server` object and then call
its `listen` method to tell it what port to listen on.

    var server = pop3.createServer('example.com');
    server.listen(110);

To form an actually useful service the application must implement authentication and maildrop 
management functionality by listening to events emitted by the server and invoking the provided
callbacks.  The first parameter to almost every event is `user` as a string, this should be used
by the application to identify the appropriate mailbox to take action on.

### Event: 'authenticate'

- user: a string (as given to `USER` or `APOP`)
- password: either a plaintext password or a an APOP style hash
- method: string indicating command used to provide password (`"PASS"` or `"APOP"`)
- hashfunc: a method that applied to a plaintext secret known to the server should yield a match to password
- callback: function taking a boolean indicating success or failure of authentication

In its most common form POP3 accepts passwords in two ways, neither of which is
particularly secure.  With the `APOP` command the password is an MD5 hash of the
password prepended with a connection specific salt, in this case `hashfunc` will
implement that hash.  With the `PASS` command the password is given in plaintext
(the username is given first in a separate `USER` command). In this case `hashfunc`
will be a no op, which allows a listener like the following to work in both cases:

    server.on('authenticate', function (user, password, method, hashfunc, callback)) {
      // assume get_user_password() returns a plaintext password
      ok = hashfunc(get_user_password(user)) === password
      // ok will be true iff the passwords matched
      return callback(ok);
    }

Note that while `APOP` may feel more secure (since the password isn't transmitted
in plaintext) it does require that the server *knows* the plaintext of the password
so it can feed it to the hashfunc, which is definitely a security anti-pattern.
With `PASS` the server can store a hash of the password (e.g. using bcrypt) and
apply that same hash to the given plaintext.  To prevent eavesdropping `PASS`
should probably only be used on a secure port or after an `STLS` command.

### Event: 'list'

- user: a string (as previously given to `USER` or `APOP`)
- which: optional message index, so either null or a 1-based integer
- callback: function expecting a list of integer message sizes

If `which` is null a list with the sizes for all messages in the user's mailbox
should be passed to callback.  If `which` is not null a list containing only
the matching message (or an empty list if no match) should be passed.

NOTE: this event is emitted for both the `STAT` comand and the `LIST` command.

### Event: 'uidl'

- user: a string (as previously given to `USER` or `APOP`)
- which: optional message uid, so either null or a string
- callback: function expecting a list of message uids

This method's behavior is the same as `list` except it passes the callback
a list of unique message ids instead of integer indexes. 

NOTE: UIDL is an optional feature of POP3 servers, if no listener is provided
for this event the UIDL capability will not be advertised.

### Event: 'retrieve'

- user: a string (as previously given to `USER` or `APOP`)
- which: message index (as given to `RETR`)
- callback: function expecting given message as a string

### Event: 'quit'

- user: a string (as previously given to `USER` or `APOP`)
- dele: a (potentially empty) list of message indexes to delete
- callback: function expecting a boolean (indicating success of deletion operation)

Per the original RFC a POP3 server is not supposed to actually
delete any messages until a valid `QUIT` is issued.  To support this
the connection will collect any indexes provided in `DELE` commands
and pass them all to the application with this event.

## Advanced Usage

It is possible to pass additional options to `createServer` (as an object),
as well as a listener for the `connected` event (see below).

    var options = {
        log:   console.log.bind(console, "POP3:"), // defaults to util.log
        debug: true,                               // if true logs all sent and received messages
        apop:  ...,                                // enable apop support (see below for details)
        key:   fs.readFileSync("privkey.pem"),     // passed to tls.createSecureContext()
        cert:  fs.readFileSync("cert.pem")         // passed to tls.createSecureContext()
    };
    var server = pop3.createServer('example.com', options, function (connection, callback) {
        console.log("received connection from", connection.socket.remoteAddress);
        return callback(true);
    });
    server.listen(110);

### Option: apop

This option controls whether the server advertises support for the `APOP` command by
including a salt in in the hello message.  Possible values are:

- false:    no APOP support (any falsy value including null works as well)
- true:     (this is the default) generate a per-connection salt using `crypto.randomBytes`
- string:   use the given string as the salt for all connections
- function: call the given no-argument function to generate a salt for each connection

APOP salts as sent to the client are delimited by angle brackets `<...>` (those brackets
are part of the salt, and are included when hashing).  It's also a common convention
(but not, as far as I can tell, a requirement) that the salt include the hostname of
the server (preceded by `@`).  If the string provided does not include the brackets
then the hostname as given to `createServer` will be appended (with an `@`) and the
brackets added.  The same rules are applied to the response value of the function as
to fixed values, so you could e.g. enable `APOP` for some connections and not others
(say based on the port number).  Some examples and the resulting hello message:

     // default, generate using crypto.randomBytes
     createServer("example.com")
     // +OK POP3 server ready <074a5c25397c@example.com>

     // false, no apop support
     createServer("example.com", { apop: false })
     // +OK POP3 server ready

     // function (this is roughly the salt suggested in the original RFC)
     createServer("example.com", { apop: () => [process.pid, Date.now()].join('.') })
     // +OK POP3 server ready <51400.1561405680277@example.com>

     // string without brackets, just the "random" part of the salt
     createServer("example.com", { apop: "sea" })
     // +OK POP3 server ready <sea@example.com>

     // string with brackets, used verbatim
     createServer("example.com", { apop: "<pink@himalayan>" })
     // +OK POP3 server ready <pink@himalayan>

### Event: 'connected'

- connection: a `POP3Connection` object
- callback: a function expecting a boolean

This is issued after the `POP3Server`'s underlying `net.Server`'s `connection` event but before
communcation with the client.  The connection's `net.Socket` is avaiable as `connection.socket`.
This method can be used to enforce network rules, set a custom salt, etc.  Passing any
falsy value to the callback will immediately close the connection.

It is also possible to extend/modify the behavior of the connection as it will emit a 
lower level event for each received command (e.g. you could listen to the `DELE` event
to mark messages for deletion immediately rather than waiting for the server's `quit`
event).  See the code for the full list of commands/events.

### Event: 'capabilities'

- state: string with the current state of the connection (`AUTHORIZATION` or `TRANSACTION`)
- capabilities: list of strings with capabilities for given state
- callback: a function expecting a list of strings

See [RFC 2449](https://tools.ietf.org/html/rfc2449.html#section-5) for details.
Listening to this event is optional, but it can be used to add or remove capabilities
to the list, e.g. if you implement some custom command in a `connected` listener.

## Alternatives

This module is similar in functionality to [pop3-server](/marook/pop3-server),
which is LGPL licensed if you're looking for that flavor.  If you're looking for 
a turnkey POP3 server implementation (including mail storage and authentication) 
take a look at Nodemailer's [wildduck](/nodemailer/wildduck).
