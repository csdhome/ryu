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

from Crypto.PublicKey import RSA
import hashlib
from base64 import b64decode

_authorized_certificates = {}


def is_authorized(digest):
    return digest in _authorized_certificates
    #     digest = hashlib.sha256(cert).hexdigest()
    #     return digest in _authorized_certificates
    #
    # return False


def add_authorized_client(address, cert):
    key = RSA.importKey(cert)
    der = key.publickey().exportKey('DER')
    digest = hashlib.sha256(der).hexdigest().upper()
    _authorized_certificates[digest] = (address, cert)
    return 'Added certificate to allowed clients'


def add_authorized_client_test(address, cert):
    keyder = b64decode(cert)
    key = RSA.importKey(keyder)
    der = key.publickey().exportKey('DER')
    digest = hashlib.sha256(der).hexdigest().upper()
    _authorized_certificates[digest] = (address, cert)
    return 'Added certificate to allowed clients'


def add_authorized_client_der(address, cert):
    digest = hashlib.sha256(cert).hexdigest().upper()
    _authorized_certificates[digest] = (address, cert)
    return 'Added certificate to allowed clients'


def convert_pem_to_der(cert):
    key = RSA.importKey(open('privatekey.pem').read())
    der = key.publickey().exportKey('DER')


def convert_cert(cert_file_path):
    rsa = RSA.importKey(open(cert_file_path).read())
    return rsa.publickey().exportKey('DER')


def add_test_cert():
    cert = open('/home/chansen/ca02/easy-rsa-master/easyrsa3/pki/issued/ovsdb.der').read()
    add_authorized_client_der('127.0.0.1', cert)
