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

import urllib2
import httplib
import socket
from urllib import addinfourl
import ntlm
import re
import logging

class AbstractNtlmAuthHandler(object):
    __slots__ = (
        'passwd', 'add_password', '_debuglevel', 'logger'
    )

    def __init__(self, password_mgr=None, debuglevel=0):
        """Initialize an instance of a AbstractNtlmAuthHandler.

Verify operation with all default arguments.
>>> abstrct = AbstractNtlmAuthHandler()

Verify "normal" operation.
>>> abstrct = AbstractNtlmAuthHandler(urllib2.HTTPPasswordMgrWithDefaultRealm())
"""
        if password_mgr is None:
            password_mgr = urllib2.HTTPPasswordMgr()

        self.passwd = password_mgr
        self.add_password = self.passwd.add_password
        self._debuglevel = debuglevel
        self.logger = logging.getLogger('urllib_ntlm')

    def set_logger(self, logger):
        self.logger = logger.getChild('urllib_ntlm')

    def set_http_debuglevel(self, level):
        self._debuglevel = level

    def http_error_authentication_required(self, auth_header_field, req, fp, headers):
        auth_header_value = headers.get(auth_header_field, None)
        if not auth_header_field or not auth_header_value:
            return

        if 'ntlm' not in auth_header_value.lower():
            return

        self.logger.info('NTLM Auth required: URL: %s', req.get_full_url())
        fp.close()
        return self.retry_using_http_NTLM_auth(req, auth_header_field, None, headers)

    def retry_using_http_NTLM_auth(self, req, auth_header_field, realm, headers):
        user, pw = self.passwd.find_user_password(realm, req.get_full_url())
        if pw is None:
            self.logger.warning('No login/password found for: URL: %s', req.get_full_url())
            return

        self.logger.info('Found creds: %s -> user=%s', req.get_full_url(), user)

        user_parts = user.split('\\', 1)
        if len(user_parts) == 1:
            UserName = user_parts[0]
            DomainName = ''
            type1_flags = ntlm.NTLM_TYPE1_FLAGS & ~ntlm.NTLM_NegotiateOemDomainSupplied
        else:
            DomainName = user_parts[0].upper()
            UserName = user_parts[1]
            type1_flags = ntlm.NTLM_TYPE1_FLAGS

        # ntlm secures a socket, so we must use the same socket for the complete handshake
        headers = dict(req.headers)
        headers.update(req.unredirected_hdrs)
        auth = 'NTLM %s' % ntlm.create_NTLM_NEGOTIATE_MESSAGE(
            user, type1_flags)

        if req.headers.get(self.auth_header, None) == auth:
            self.logger.info('Auth header already present: %s', req.get_full_url())
            return None

        headers[self.auth_header] = auth

        host = req.get_host()
        if not host:
            raise urllib2.URLError('no host given')

        h = None
        if req.get_full_url().startswith('https://'):
            h = httplib.HTTPSConnection(host)  # will parse host:port
        else:
            h = httplib.HTTPConnection(host)  # will parse host:port

        h.set_debuglevel(self._debuglevel)
        # we must keep the connection because NTLM authenticates the
        # connection, not single requests
        headers["Connection"] = "Keep-Alive"
        headers = dict((name.title(), val)
                        for name, val in headers.items())
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
        auth_header_value = r.getheader(auth_header_field, None)

        # some Exchange servers send two WWW-Authenticate headers, one with the NTLM challenge
        # and another with the 'Negotiate' keyword - make sure we operate on the right one
        m = re.match('(NTLM [A-Za-z0-9+\-/=]+)', auth_header_value)
        if m:
            auth_header_value, = m.groups()

        ServerChallenge, NegotiateFlags = ntlm.parse_NTLM_CHALLENGE_MESSAGE(
            auth_header_value[5:])

        auth = 'NTLM %s' % ntlm.create_NTLM_AUTHENTICATE_MESSAGE(
            ServerChallenge, UserName, DomainName, pw, NegotiateFlags)

        headers[self.auth_header] = auth
        headers["Connection"] = "Close"
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
                    'Authentication failed: URL=%s, CODE=%s, AUTH=%s',
                    req.get_full_url(), infourl.code, auth
                )
            else:
                self.logger.info('Authentication OK: URL=%s', req.get_full_url())

            return infourl

        except socket.error, err:
            raise urllib2.URLError(err)


class HTTPNtlmAuthHandler(AbstractNtlmAuthHandler, urllib2.BaseHandler):

    auth_header = 'Authorization'

    def http_error_401(self, req, fp, code, msg, headers):
        try:
            return self.http_error_authentication_required('www-authenticate', req, fp, headers)
        except Exception as e:
            self.logger.exception(
                'HTTPNtlmAuthHandler (url=%s): %s', req.get_full_url(), e)


class ProxyNtlmAuthHandler(AbstractNtlmAuthHandler, urllib2.BaseHandler):
    """
        CAUTION: this class has NOT been tested at all!!!
        use at your own risk
    """
    auth_header = 'Proxy-authorization'

    def http_error_407(self, req, fp, code, msg, headers):
        try:
            return self.http_error_authentication_required('proxy-authenticate', req, fp, headers)
        except Exception as e:
            self.logger.exception(
                'ProxyNtlmAuthHandler (url=%s): %s', req.get_full_url(), e)
