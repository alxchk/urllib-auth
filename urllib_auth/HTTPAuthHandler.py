# This library is free software: you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later version.

# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.  If not, see <http://www.gnu.org/licenses/> or <http://www.gnu.org/licenses/lgpl.txt>.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys
import socket
import re
import ssl
import logging


if sys.version_info.major > 2:
    from urllib.response import addinfourl
    from urllib.request import BaseHandler, HTTPPasswordMgr
    from urllib.request import (
        ProxyDigestAuthHandler, AbstractBasicAuthHandler,
        AbstractDigestAuthHandler
    )
    from urllib.parse import urlparse
    from urllib.error import URLError, HTTPError
    from http.client import HTTPSConnection, HTTPConnection

    def infourl_to_sock(infourl):
        return infourl.fp.raw._sock

else:
    from urllib import addinfourl
    from urllib2 import BaseHandler, HTTPPasswordMgr, URLError, HTTPError
    from urllib2 import urlparse
    from urllib2 import (
        AbstractBasicAuthHandler, AbstractDigestAuthHandler
    )
    from httplib import HTTPSConnection, HTTPConnection

    def infourl_to_sock(infourl):
        return infourl.fp._sock.fp._sock


from .auth import (
    Authentication, METHOD_NTLM, METHOD_NEGOTIATE,
    AuthenticationError,
    get_supported_methods
)


def infourl_to_ssl_context(infourl):
    sock = infourl_to_sock(infourl)
    if not isinstance(sock, ssl.SSLSocket):
        return None

    return sock.context


def infourl_to_ssl_certificate(infourl):
    sock = infourl_to_sock(infourl)
    if not isinstance(sock, ssl.SSLSocket):
        return None

    return sock.getpeercert(True)


def make_infourl(response, req, fp=None):
    def notimplemented():
        raise NotImplementedError

    response.readline = notimplemented
    infourl = addinfourl(
        fp or response, response.msg, req.get_full_url())
    infourl.code = response.status
    infourl.msg = response.reason
    return infourl


def consume_response_body(response):
    content_length = response.getheader('content-length')
    if content_length:
        content_length = int(content_length)

        # Finish previous response
        response.begin()
        response._safe_read(content_length)

        # remove the reference to the socket, so that it can not be closed
        # by the response object (we want to keep the socket open)
        response.fp = None


class AbstractAuthHandler(Authentication):
    __slots__ = (
        'passwd', 'add_password', 'parent', '_debuglevel',
        '_basic', '_digest'
    )

    auth_header_request = None
    auth_header_response = None

    def __init__(self, password_mgr=None, debuglevel=0):
        """Initialize an instance of a AbstractAuthHandler.

Verify operation with all default arguments.
>>> abstrct = AbstractAuthHandler()

Verify "normal" operation.
>>> abstrct = AbstractAuthHandler(urllib2.HTTPPasswordMgrWithDefaultRealm())
"""
        super(AbstractAuthHandler, self).__init__(
            logging.getLogger('urllib_auth')
        )

        if password_mgr is None:
            password_mgr = HTTPPasswordMgr()

        self.parent = None
        self.passwd = password_mgr
        self.add_password = self.passwd.add_password

        self._debuglevel = debuglevel

        self._basic = AbstractBasicAuthHandler(password_mgr=self.passwd)
        self._digest = AbstractDigestAuthHandler(passwd=self.passwd)

    def add_parent(self, parent):
        self.parent = parent

        for default in (self._basic, self._digest):
            setattr(default, 'auth_header', self.auth_header_response)
            setattr(default, 'parent', parent)

    def set_logger(self, logger):
        self.logger = logger.getChild('urllib_auth')

    def set_http_debuglevel(self, level):
        self._debuglevel = level

    def get_authentication_methods(self, headers, extra):
        methods = set()

        if sys.version_info.major > 2:
            values = headers.get_all(self.auth_header_response)
        else:
            values = headers.getheaders(self.auth_header_response)

        for value in values:
            methods.add(value)

        supported, unsupported = get_supported_methods(methods, extra)

        return supported, unsupported

    def http_error_authentication_required(self, target, req, infourl, headers):


        extra = {
            'method': req.get_method(),
            'host': req.host,
            'selector': req.selector
            if sys.version_info.major > 2 else req.get_selector(),
            'url': req.get_full_url()
        }

        methods, unsupported = self.get_authentication_methods(headers, extra)
        if not methods:
            self.logger.warning(
                'No supported auth method: Target=%s, methods=%s, headers=%s',
                target, unsupported, headers)
            return

        self.logger.info(
            'Auth required: Target: %s (methods: supported=%s, unsupported=%s)',
            target, methods, unsupported
        )

        return self.retry_using_http_auth(req, infourl, methods, headers)

    def retry_using_http_auth(self, req, infourl, auth_methods, headers):
        connection = headers.get('connection')

        # ntlm secures a socket, so we must use the same socket for the complete handshake
        headers = dict(req.headers)
        headers.update(req.unredirected_hdrs)

        url = req.get_full_url()
        host = req.host

        if not host:
            raise URLError('no host given')

        user, pw = self.passwd.find_user_password(None, url)
        domain = None
        if user is not None and '\\' in user:
            domain, user = user.split('\\', 1)

        certificate = infourl_to_ssl_certificate(infourl)

        try:
            more, method, payload = self.create_auth1_message(
                domain, user, pw, url, auth_methods, certificate)

        except AuthenticationError:
            self.logger.warning(
                'No way to perform authentication: URL=%s', url)
            return None

        self.logger.debug(
            'Selected auth method=%s payload=%s', method, payload
        )

        headers.update({
            self.auth_header_request: ' '.join([method, payload]),
            'Connection': 'keep-alive' if more else 'close'
        })

        h = None

        if url.startswith('https://'):
            try:
                old_ssl_context = infourl_to_ssl_context(infourl)
                self.logger.debug('Reuse SSL Context: %s', old_ssl_context)
            except Exception as e:
                self.logger.exception('SSL Context not found')
                old_ssl_context = None

            h = HTTPSConnection(host, context=old_ssl_context)
        else:
            h = HTTPConnection(host)

        if self._debuglevel or self.logger.getEffectiveLevel() == logging.DEBUG:
            h.set_debuglevel(1)

        if connection and connection.lower() == 'close':
            self.logger.debug(
                'New connection required: host=%s', host
            )

            infourl.close()
            infourl = None
        else:
            self.logger.debug('Reuse connection %s')
            h.sock = infourl_to_sock(infourl)

        # We must keep the connection because NTLM authenticates the
        # connection, not single requests

        headers = dict(
            (name.title(), val)
            for name, val in headers.items()
        )

        self.logger.debug('Send request, headers=%s', headers)

        payload = None

        if sys.version_info.major > 2:
            selector = req.selector
        else:
            selector = req.get_selector()

        h.request(req.get_method(), selector, req.data, headers)
        response = h.getresponse()

        if response.getheader('set-cookie'):
            # this is important for some web applications that store authentication-related
            # info in cookies (it took a long time to figure out)
            headers['Cookie'] = response.getheader('set-cookie')

        # some Exchange servers send two WWW-Authenticate headers, one with the NTLM challenge
        # and another with the 'Negotiate' keyword - make sure we operate on the right one

        expected_header = self.auth_header_response.lower()

        for header, value in response.getheaders():
            if header.lower() != expected_header:
                self.logger.debug(
                    'Not matched header: %s = %s (!= %s)',
                    header.lower(), value, expected_header
                )
                continue

            match = re.match(
                r'^(?:{}\s+)?([A-Za-z0-9+\-/=]+)$'.format(method),
                value, re.IGNORECASE
            )
            if not match:
                self.logger.debug('Not matched value: %s = %s', header, value)
                continue

            payload, = match.groups()

        if more:
            if not payload:
                self.logger.error(
                    'Auth header response not found, Status=%s URL=%s',
                    response.status, url)

                return None

            self.logger.debug('Step2: Method: %s, Payload: %s', method, payload)

            try:
                more, method, payload = self.create_auth2_message(payload)
            except AuthenticationError as e:
                self.logger.error('Step2: Authentication failed (%s)', e)
                return None

        if more:
            self.logger.debug(
                'Step2: Method: %s, Response Payload: %s', method, payload)
            headers[self.auth_header_request] = ' '.join([method, payload])

            try:
                consume_response_body(response)

                if sys.version_info.major > 2:
                    selector = req.selector
                else:
                    selector = req.get_selector()

                h.request(req.get_method(), selector, req.data, headers)
                # none of the configured handlers are triggered, for example
                # redirect-responses are not handled!
                response = h.getresponse()

            except socket.error as err:
                self.logger.exception('')
                raise URLError(err)

        else:
            self.logger.debug(
                'Step2: Method: %s, Continuation not required', method
            )

        infourl = make_infourl(response, req)
        if infourl.code in (401, 407):
            self.logger.warning(
                'Authentication failed: URL=%s, CODE=%s',
                req.get_full_url(), infourl.code
            )
        else:
            self.logger.info('Authentication OK: URL=%s', req.get_full_url())

        return infourl


class HTTPAuthHandler(AbstractAuthHandler, BaseHandler):

    auth_header_request = 'Authorization'
    auth_header_response = 'www-authenticate'
    auth_is_proxy = False

    def http_error_401(self, req, fp, code, msg, headers):
        url = req.get_full_url()

        try:
            return self.http_error_authentication_required(url, req, fp, headers)
        except Exception as e:
            self.logger.exception(
                'HTTPAuthHandler (url=%s): %s', url, e)


class ProxyAuthHandler(AbstractAuthHandler, BaseHandler):
    """
        CAUTION: this class has NOT been tested at all!!!
        use at your own risk
    """

    auth_header_request = 'proxy-authorization'
    auth_header_response = 'proxy-authenticate'
    auth_is_proxy = True

    def http_error_407(self, req, fp, code, msg, headers):
        host = req.host

        try:
            return self.http_error_authentication_required(host, req, fp, headers)
        except Exception as e:
            self.logger.exception(
                'ProxyAuthHandler (Host=%s): %s', host, e)
