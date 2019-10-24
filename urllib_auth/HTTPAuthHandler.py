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

import urlparse
import urllib2
import httplib
import socket
import ntlm
import re
import logging

from urllib import addinfourl

from .auth import (
    Authentication, METHOD_NTLM, METHOD_NEGOTIATE,
    CONTINUE, AuthenticationError
)

class AbstractAuthHandler(Authentication):
    __slots__ = (
        'passwd', 'add_password', '_debuglevel'
    )

    auth_header = None
    auth_header_field = None

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
            password_mgr = urllib2.HTTPPasswordMgr()

        self.passwd = password_mgr
        self.add_password = self.passwd.add_password

        self._debuglevel = debuglevel

    def set_logger(self, logger):
        self.logger = logger.getChild('urllib_auth')

    def set_http_debuglevel(self, level):
        self._debuglevel = level
    
    def http_error_authentication_required(self, req, fp, headers):
        methods = set()
        unsupported = set()
        url = req.get_full_url()

        for header in headers.getallmatchingheaders(self.auth_header_field):
            _, value = header.split(':', 1)
            values = tuple(x.strip().lower() for x in value.split(','))
            for value in values:
                if value == 'ntlm':
                    methods.add(METHOD_NTLM)
                elif value == 'negotiate':
                    methods.add(METHOD_NEGOTIATE)
                else:
                    unsupported.add(value)
        
        if not methods:
            self.logger.warning(
                'No supported auth method: URL=%s, methods=%s',
                url, unsupported)
            return

        self.logger.info(
            'Auth required: URL: %s (methods: supported=%s, unsupported=%s)',
            url, ','.join(methods), ','.join(unsupported)
        )

        fp.close()
        return self.retry_using_http_auth(req, methods, headers)

    def retry_using_http_auth(self, req, auth_methods, headers):

        # ntlm secures a socket, so we must use the same socket for the complete handshake
        headers = dict(req.headers)
        headers.update(req.unredirected_hdrs)

        url = req.get_full_url()
        host = req.get_host()
        if not host:
            raise urllib2.URLError('no host given')

        user, pw = self.passwd.find_user_password(None, url)
        domain = None
        if user is not None and '\\' in user:
            domain, user = user.split('\\', 1)

        try:
            result, method, payload = self.create_auth1_message(
                domain, user, pw, url, auth_methods)
            if result != CONTINUE:
                self.logger.error('Something went wrong? %s', result)
                return None

        except AuthenticationError:
            self.logger.warning('No way to perform authentication: URL=%s', url)
            return None
    
        headers[self.auth_header] = ' '.join([method, payload])

        h = None
        if url.startswith('https://'):
            h = httplib.HTTPSConnection(host)
        else:
            h = httplib.HTTPConnection(host)

        h.set_debuglevel(self._debuglevel)
    
        # We must keep the connection because NTLM authenticates the
        # connection, not single requests

        headers = dict(
            (name.title(), val)
            for name, val in headers.items()
        )
        headers['Connection'] = 'Keep-Alive'
    
        h.request(req.get_method(), req.get_selector(), req.data, headers)
        r = h.getresponse()
        r.begin()
        r._safe_read(int(r.getheader('content-length')))

        if r.getheader('set-cookie'):
            # this is important for some web applications that store authentication-related
            # info in cookies (it took a long time to figure out)
            headers['Cookie'] = r.getheader('set-cookie')

        # remove the reference to the socket, so that it can not be closed
        # by the response object (we want to keep the socket open)
        r.fp = None
        
        # some Exchange servers send two WWW-Authenticate headers, one with the NTLM challenge
        # and another with the 'Negotiate' keyword - make sure we operate on the right one
        payload = None

        for header, value in r.getheaders():
            if header.lower() != self.auth_header_field.lower():
                continue

            match = re.match(
                ' '.join([method, r'([A-Za-z0-9+\-/=]+)']), value
            )
            if not match:
                continue
        
            payload, = match.groups()
        
        if not payload:
            self.logger.error('Auth header response not found, URL=%s', url)
            return None

        _, method, payload = self.create_auth2_message(payload)

        headers[self.auth_header] = ' '.join([method, payload])
        headers['Connection'] = 'Close'
        headers = dict((name.title(), val)
                        for name, val in headers.items())

        try:
            h.request(req.get_method(), req.get_selector(),
                        req.data, headers)
            # none of the configured handlers are triggered, for example
            # redirect-responses are not handled!
            response = h.getresponse()

            def notimplemented():
                raise NotImplementedError

            response.readline = notimplemented
            infourl = addinfourl(
                response, response.msg, req.get_full_url())
            infourl.code = response.status
            infourl.msg = response.reason

            if infourl.code in (401, 407):
                self.logger.warning(
                    'Authentication failed: URL=%s, CODE=%s',
                    req.get_full_url(), infourl.code
                )
            else:
                self.logger.info('Authentication OK: URL=%s', req.get_full_url())

            return infourl

        except socket.error, err:
            raise urllib2.URLError(err)


class HTTPAuthHandler(AbstractAuthHandler, urllib2.BaseHandler):

    auth_header = 'Authorization'
    auth_header_field = 'www-authenticate'

    def http_error_401(self, req, fp, code, msg, headers):
        try:
            return self.http_error_authentication_required(req, fp, headers)
        except Exception as e:
            self.logger.exception(
                'HTTPAuthHandler (url=%s): %s', req.get_full_url(), e)


class ProxyAuthHandler(AbstractAuthHandler, urllib2.BaseHandler):
    """
        CAUTION: this class has NOT been tested at all!!!
        use at your own risk
    """
    auth_header = 'Proxy-authorization'
    auth_header_field = 'proxy-authenticate'

    def http_error_407(self, req, fp, code, msg, headers):
        try:
            return self.http_error_authentication_required(req, fp, headers)
        except Exception as e:
            self.logger.exception(
                'ProxyAuthHandler (url=%s): %s', req.get_full_url(), e)
