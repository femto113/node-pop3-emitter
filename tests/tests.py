#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import print_function

import sys
from poplib import POP3, error_proto
from email.parser import Parser
import unittest
import json
import random
import re

PORT = 110

# TODO:
# tests for remaining commands supported by poplib
#     POP3.rpop(user) # Not supported, should always err or does capa handle this case?
#     POP3.utf8()
# test mailbox locking?

class POP3TestCase(unittest.TestCase):
    """base class for other tests, handles connecting and quitting"""
    def assertIn(self, a, b, *args, **kwargs):
        # the python3 version of poplib returns bytes not strings, so for
        # 2/3 compatibility, decode everything before comparing
        if callable(getattr(a, 'decode', None)):
            a = a.decode()
        if type(b) in (tuple, list):
            b = map(lambda s: callable(getattr(s, 'decode', None)) and s.decode() or s, b)
        elif callable(getattr(b, 'decode', None)):
            b = b.decode()
        return super(POP3TestCase, self).assertIn(a, b, *args, **kwargs)

    def assertOk(self, result):
      # results are sometimes strings and sometime tuples
      self.assertIn('+OK', result)

    def assertErr(self, result):
      # results are sometimes strings and sometime tuples
      self.assertIn('-ERR', result)

    def setUp(self):
        self.pop3 = POP3('localhost', PORT)
        with open('mailboxes.json', 'r') as f:
            self.mailboxes = json.load(f)
            self.addresses = sorted(self.mailboxes.keys())
        # Turning this on will echo the full conversation, useful for debugging
        # self.pop3.set_debuglevel(True)

    def tearDown(self):
        self.pop3.quit()
        del self.pop3

    # this is the same regex poplib uses to extract the salt
    salty = re.compile(r'\+OK.*(<[^>]+>)')

    def authenticate(self, user, password):
        """flexible authentication, use APOP if server supports it, else USER & PASS"""
        if self.salty.match(self.pop3.getwelcome().decode()):
            self.assertOk(self.pop3.apop(user, password));
        else:
            self.assertOk(self.pop3.user(user));
            self.assertOk(self.pop3.pass_(password));

class PreAuthTests(POP3TestCase):
    """Test POP3 pre-auth interactions"""

    def testWelcome(self):
        response = self.pop3.getwelcome()
        # TODO: is there any truly canonical text in POP3 welcome?
        self.assertIn("ready", response);

    @unittest.skipUnless(sys.version_info >= (3,4), "capa() added in 3.4")
    def testCapa(self):
        response = self.pop3.capa()
        # no capabilities are guaranteed, so not much of an assertion to be made here
        self.assertTrue(isinstance(response, dict))
        
    @unittest.skipUnless(sys.version_info >= (3,4), "stls() added in 3.4")
    def testStls(self):
        response = self.pop3.stls()
        self.assertOk(response)

class PostAuthTests(POP3TestCase):
    """Test POP3 mail listing and retrieval methods"""

    def setUp(self):
        super(PostAuthTests, self).setUp()
        # pick one of the first three users (alice, bob, carol), who should all have messages
        self.user = random.choice(self.addresses[:3])
        self.authenticate(self.user, self.mailboxes[self.user]["password"])
        # NOTE: capa() was added in 3.4
        if callable(getattr(self.pop3, 'capa', None)):
            self.capa = self.pop3.capa()
        else:
            # assume UIDL
            self.capa = { "UIDL": [] }

    def testNoop(self):
        response = self.pop3.noop()
        self.assertOk(response)

    def testStat(self):
        """The server responds to a valid STAT command with a list of messages."""
        num_messages, num_bytes = self.pop3.stat()
        # Shortest possible message?
        min_bytes = len('From:') + len('To:') + len('Subject:')
        self.assertTrue(num_bytes >= num_messages * min_bytes)

    def testListWithNoArg(self):
        """The server responds to a no-arg LIST command with a list of messages."""
        status, messages, size = self.pop3.list()
        # first item in response tuple is status
        self.assertOk(status)
        # second item in response tuple is list of message numbers and sizes
        # third item in response tuple is total size of response?
        # TODO: any other assertions to be made?

    def testListWithInRangeIndex(self):
        """The server responds to a LIST with an in-range arg with the given message."""
        response = self.pop3.list(1)
        print(response)
        # first item in response tuple is status
        self.assertOk(response)
        # second item in response tuple is list of message numbers and sizes
        # third item in response tuple is total size of response?
        # TODO: any other assertions to be made?

    def testListWithOutOfRangeIndex(self):
        """The server responds to a LIST with an out-of-range arg with an error."""
        with self.assertRaises(error_proto):
            self.pop3.list(99999)

    def testUidl(self):
        """The server responds to a UIDL command."""
        if "UIDL" in self.capa:
            response = self.pop3.uidl()
            self.assertOk(response)

    def testRetr(self):
        """The server responds to a RETR command."""
        response, lines, size = self.pop3.retr(1)
        self.assertOk(response)
        # make sure we got an email that was sent to the correct user
        m = Parser().parsestr("\n".join(map(lambda l: l.decode(), lines)))
        self.assertIn(self.user, m["to"])
        # make sure we got the whole body
        if callable(getattr(m, 'get_body', None)):
            body = m.get_body(preferencelist=('plain',))
        else:
            body = m.get_payload()
        print(json.dumps(body));

    def testTop(self):
        n = 1
        response, lines, size = self.pop3.top(1, n)
        self.assertOk(response)
        # parse the result
        m = Parser().parsestr("\r\n".join(map(lambda l: l.decode(), lines)))
        # make sure we got an email that was sent to the correct user
        self.assertIn(self.user, m["to"])
        # check to see if we got just one line of the body
        if callable(getattr(m, 'get_body', None)):
            body = m.get_body(preferencelist=('plain',))
        else:
            body = m.get_payload()
        # body should be newline delimited at this point
        self.assertEqual(len(body.split('\n')), n)

class DeleteTests(POP3TestCase):
    """long form tests of delete related flow"""
    def testDeleQuitRset(self):
        self.user = 'delete@example.com'
        self.assertIn(self.user, self.addresses)
        self.authenticate(self.user, self.mailboxes[self.user]["password"])
        orig_count, _ = self.pop3.stat()
        self.assertTrue(orig_count > 1)
        response, sizes, _ = self.pop3.list()
        self.assertOk(response)
        # to begin with sizes should be equal
        self.assertEqual(len(sizes), orig_count)
        deleted = {s.split()[0]:False for s in sizes}
        self.assertEqual(len(deleted), orig_count)
        # pick a non-deleted message and delete it
        which = 1 # TODO: at random?
        response = self.pop3.dele(which)
        self.assertOk(response);
        # pick an already deleted message and try to delete it again
        with self.assertRaises(error_proto):
            response = self.pop3.dele(1)
        # quit, which should finalize the deletion
        self.tearDown()

        # now reconnect, server should have effected the deletes
        self.setUp()
        self.authenticate(self.user, self.mailboxes[self.user]["password"])
        dele_count, new_total = self.pop3.stat()
        self.assertEqual(dele_count, orig_count - 1)

        # pick a message and delete it
        which = 1 # TODO: at random?
        self.assertOk(self.pop3.dele(which))
        # but RSET
        self.assertOk(self.pop3.rset())
        # quit again, no deletes should happen
        self.tearDown()
        # reconnect again, server should not have deleted anything this time
        self.setUp()
        self.authenticate(self.user, self.mailboxes[self.user]["password"])
        rset_count, rset_total = self.pop3.stat()
        self.assertEqual(rset_count, dele_count);

    def testDeleNoQuit(self):
        """server should not commit deletes if quit didn't happen"""
        self.user = 'delete@example.com'
        self.assertIn(self.user, self.addresses)
        self.authenticate(self.user, self.mailboxes[self.user]["password"])
        orig_count, _ = self.pop3.stat()
        self.assertTrue(orig_count > 1)
        self.assertOk(self.pop3.dele(1))
        # close without quiting (close() method added in 3.X)
        if callable(getattr(self.pop3, 'close', None)):
            self.pop3.close()
        else: 
            # mimics quit() from 2.X poplib.py
            self.pop3.file.close()
            self.pop3.sock.close()
        del self.pop3
        # now reconnect, server should have not have effected the deletes
        self.setUp()
        self.authenticate(self.user, self.mailboxes[self.user]["password"])
        count, _ = self.pop3.stat()
        self.assertEqual(count, orig_count)

if __name__ == "__main__":
    unittest.main()
