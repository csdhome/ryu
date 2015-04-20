# Copyright (c) 2014 Rackspace Hosting
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from eventlet.green.OpenSSL import SSL
from ryu.services.protocols.ovsdb import auth


class Connection(SSL.Connection):
    def accept(self):
        sock, client_address = SSL.Connection.accept(self)
        sock.do_handshake()
        return sock, client_address


def wrap_socket(crt, key, sock):
    context = SSL.Context(SSL.SSLv23_METHOD)
    context.use_certificate_file(crt)
    context.use_privatekey_file(key)

    def verify(conn, cert, errnum, depth, ok):
        digest = cert.digest('sha256')
        digest = digest.replace(':', '')
        digest = digest.replace(' ', '')
        digest = digest.upper()
        return auth.is_authorized(digest)

    opts = (SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT |
            SSL.VERIFY_CLIENT_ONCE)

    context.set_verify(opts, verify)
    context.set_verify_depth(0)

    conn = Connection(context, sock)
    conn.set_accept_state()
    return conn