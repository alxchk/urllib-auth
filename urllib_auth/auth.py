from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__all__ = (
    'METHOD_NTLM', 'METHOD_NEGOTIATE', 'METHOD_KERBEROS',
    'KerberosBackend',
    'AuthenticationError', 'Authentication',
    'get_supported_methods'
)

import sys
import hashlib

if sys.version_info.major > 2:
    from urllib.parse import urlparse
    string_types = (str)
else:
    from urlparse import urlparse
    string_types = (unicode)

from collections import namedtuple
from base64 import b64encode, b64decode

from ntlm_auth.ntlm import NtlmContext
from ntlm_auth.gss_channel_bindings import GssChannelBindingsStruct

from .digest import make_digest_response

Result = namedtuple('Result', ('more', 'method', 'payload'))
Method = namedtuple('Method', ('id', 'args'))
Args = namedtuple('Args', ('default', 'extra'))

class Method(object):
    __slots__ = ('id', 'args', 'priority')

    def __init__(self, id, args, priority):
        self.id = id
        self.args = args
        self.priority = priority

    def __lt__(self, other):
        return self.priority < other.priority

    def __repr__(self):
        return 'Metod({}, {}, {})'.format(
            repr(self.id), repr(self.args), repr(self.priority)
        )


METHOD_NTLM = 'NTLM'
METHOD_NEGOTIATE = 'Negotiate'
METHOD_KERBEROS = 'Kerberos'
METHOD_BASIC = 'Basic'
METHOD_DIGEST = 'Digest'

METHODS_PRIORITY_SECURE = (
    METHOD_KERBEROS, METHOD_NEGOTIATE, METHOD_NTLM,
    METHOD_DIGEST, METHOD_BASIC
)

METHODS_PRIORITY_SIMPLE = (
    METHOD_BASIC, METHOD_DIGEST, METHOD_NTLM,
    METHOD_NEGOTIATE, METHOD_KERBEROS
 )

METHODS_KERBEROS = (METHOD_KERBEROS, METHOD_NEGOTIATE)


class KerberosBackend(object):
    __slots__ = (
        'kerberos',
        'CONTINUE', 'COMPLETE',
        'has_sspi_ntlm_support',
        'has_sspi_nego_support',
        'has_gssapi_support'
    )

    def __init__(self):
        self.has_gssapi_support = False
        self.has_sspi_ntlm_support = False
        self.has_sspi_nego_support = False

        self.CONTINUE = 0
        self.COMPLETE = 1
        self.kerberos = None

        try:
            if sys.platform != 'win32':
                raise NotImplementedError()

            self.kerberos = __import__('winkerberos')
            self.has_sspi_ntlm_support = True
            self.has_sspi_nego_support = True

        except (ImportError, NotImplementedError):
            try:
                self.kerberos = __import__('kerberos')

                self.has_gssapi_support = True

            except ImportError:
                self.kerberos = None

    def __getattr__(self, attr):
        if self.kerberos:
            return getattr(self.kerberos, attr)


_CACHED_KERBEROS_BACKEND = None

def _get_kerberos_backend():
    global _CACHED_KERBEROS_BACKEND

    if _CACHED_KERBEROS_BACKEND is None:
        _CACHED_KERBEROS_BACKEND = KerberosBackend()

    return _CACHED_KERBEROS_BACKEND


def _get_method(method, extra={}, priorities=METHODS_PRIORITY_SECURE):
    if isinstance(method, Method):
        return method

    method_id = None
    method_args = None

    if ' ' in method:
        method_id, method_args = method.split(' ', 1)
        method_id = method_id.lower()
    else:
        method_id = method.lower()

    for idx, known_method in enumerate(priorities):
        if method_id == known_method.lower():
            return Method(
                known_method, Args(method_args, extra), idx
            )


def get_supported_methods(methods, extra, secure=True):
    priorities = METHODS_PRIORITY_SECURE if secure else METHODS_PRIORITY_SIMPLE

    supported = []
    unsupported = []

    for method in methods:
        parsed_method = _get_method(method, extra, priorities)

        if parsed_method:
            supported.append(parsed_method)
        else:
            unsupported.append(method)

    supported = sorted(supported)

    return supported, unsupported


class AuthenticationError(Exception):
    pass


class Authentication(object):
    __slots__ = (
        'logger',
        '_ctx', '_method', '_sspi',

        '_channel_bindings',

        '_args',
        '_user', '_domain', '_password',
        '_kerberos'
    )

    def __init__(self, logger, kerberos=None):
        self.logger = logger
        self._ctx = None
        self._method = None
        self._sspi = False
        self._channel_bindings = None
        self._kerberos = kerberos

        if self._kerberos is None:
            self._kerberos = _get_kerberos_backend()

    def _create_auth1_message_sspi(
            self, url, method_data, user=None,
            password=None, domain=None, flags=0,
            certificate=None):

        if isinstance(method_data, Method):
            method = method_data.id
        else:
            method = method_data

        server = None
        principal = None

        kwargs = {
            'user': user,
            'password': password,
            'domain': domain,
            'gssflags': flags
        }

        parsed = urlparse(url)
        host = parsed.netloc
        scheme = parsed.scheme.upper()
        hostname = host.rsplit(':', 1)[0]

        if scheme.startswith('HTTP'):
            service = 'HTTP'
        else:
            service = scheme

        need_inquire_cred = False

        if (self._kerberos.has_sspi_nego_support or
            self._kerberos.has_gssapi_support) and method in (
                METHOD_NEGOTIATE, METHOD_KERBEROS):

            if certificate:
                self.set_certificate(certificate)

            if method == METHOD_NEGOTIATE:
                mech_oid = self._kerberos.GSS_MECH_OID_SPNEGO
            else:
                mech_oid = self._kerberos.GSS_MECH_OID_KRB5

            flags |= \
                self._kerberos.GSS_C_MUTUAL_FLAG | \
                self._kerberos.GSS_C_SEQUENCE_FLAG

            kwargs.update({
                'mech_oid': mech_oid,
                'gssflags': flags
            })

            server = service + '@' + hostname

            if self._kerberos.has_gssapi_support:
                del kwargs['user']
                del kwargs['domain']

                if user and domain and '@' not in user:
                    principal = user + '@' + domain
                else:
                    principal = user

                if not kwargs['password']:
                    need_inquire_cred = True
                    del kwargs['password']

        elif self._kerberos.has_sspi_ntlm_support and method == METHOD_NTLM:
            # This is only for SSPI
            kwargs['mech_oid'] = self._kerberos.GSS_MECH_OID_NTLM
            server = hostname

        else:
            raise NotImplementedError('No supported auth methods')

        result = 0

        try:
            result, self._ctx = self._kerberos.authGSSClientInit(
                server, principal, **kwargs
            )

        except TypeError as e:
            self.logger.error(
                'GSSAPI: authGSSClientInit: failed to set password: %s', e
            )

            if password:
                raise NotImplementedError(
                    "ccs-pykerberos doesn't support password auth")

            del kwargs['password']
            result, self._ctx = self._kerberos.authGSSClientInit(
                server, principal, **kwargs
            )

        if result < 0:
            self.logger.error('GSSAPI: authGSSClientInit Result: %d', result)
            raise AuthenticationError(result)

        self.logger.debug(
            'GSSAPI: New context for SPN=%s%s (need inquire creds: %s)', server,
            '' if not principal else 'Principal='+principal, need_inquire_cred
        )

        if need_inquire_cred:
            result = self._kerberos.authGSSClientInquireCred(self._ctx)
            if result < 0:
                raise AuthenticationError(result)

            self.logger.warning(
                'GSSAPI: Using principal: %s',
                self._kerberos.authGSSClientUserName(self._ctx),
            )

        kwargs = {}
        if self._channel_bindings:
            kwargs['channel_bindings'] = self._channel_bindings

        result = self._kerberos.authGSSClientStep(
            self._ctx, '', **kwargs
        )

        if result < 0:
            self.logger.error('GSSAPI: authGSSClientInit Result: %d', result)
            raise AuthenticationError(result)

        self._method = method
        self._sspi = True

        return Result(
            result == self._kerberos.CONTINUE,
            self._method,
            self._kerberos.authGSSClientResponse(self._ctx)
        )

    def _create_auth2_message_sspi(self, payload):
        kwargs = {}
        if self._channel_bindings:
            kwargs['channel_bindings'] = self._channel_bindings

        result = self._kerberos.authGSSClientStep(
            self._ctx, payload, **kwargs
        )

        payload = self._kerberos.authGSSClientResponse(self._ctx)

        if result < 0:
            self.logger.error(
                'GSSAPI: authGSSClientStep (2) Step Result: %d', result)
            raise AuthenticationError(result)
        elif result == self._kerberos.COMPLETE:
            if payload is not None:
                if self._method != METHOD_NTLM:
                    # Known bug for NTLM and winkerberos
                    self.logger.warning(
                        'GSSAPI: API bug: payload provided but step is not required')
                result = self._kerberos.CONTINUE
            else:
                self.logger.info(
                    'GSSAPI: authGSSClientStep (2) not required for %s',
                    self._method)

        return Result(
            result == self._kerberos.CONTINUE,
            self._method,
            payload
        )

    def set_certificate(self, certificate):
        # FIXME: Handle case with different hash function somehow..

        application_data = b'tls-server-end-point:' + hashlib.sha256(
            certificate).digest()

        self._channel_bindings = self._kerberos.channelBindings(
            application_data=application_data)

        self.logger.debug(
            'Set channel bindings: %s -> %s',
            repr(application_data), self._channel_bindings
        )

    def _create_auth1_message_ntlm(self, domain, user, pw, certificate):
        domain = domain or None
        workstation = None
        cbt_data = None
        ntlm_compatibility = 1

        if certificate is not None:
            ntlm_compatibility = 3

            cbt_data = GssChannelBindingsStruct()
            cbt_data[cbt_data.APPLICATION_DATA] = \
              b'tls-server-end-point:' + hashlib.sha256(
                  certificate).digest()

        self._ctx = NtlmContext(
            user, pw, domain,
            workstation,
            cbt_data,
            ntlm_compatibility
        )

        payload = b64encode(self._ctx.step()).decode('ascii')

        self._method = METHOD_NTLM

        return Result(
            True, self._method, payload
        )

    def _create_auth2_message_ntlm(self, payload):

        payload = b64encode(self._ctx.step(b64decode(payload))).decode('ascii')

        return Result(
            False, self._method, payload
        )

    def _create_auth1_message_basic(self, user, pw):
        response = b64encode((user + ':' + pw).encode('utf-8')).decode('ascii')

        self._method = METHOD_BASIC

        return Result(
            False, self._method, response
        )

    def _create_auth1_message_digest(self, domain, user, pw, args):
        response = make_digest_response(domain, user, pw, args)

        self._method = METHOD_DIGEST

        return Result(
            False, self._method, response
        )

    def create_auth1_message(
        self, domain, user, pw, url, payloads,
            certificate=None, secure=True):

        if __debug__:
            assert(not domain or isinstance(domain, string_types))
            assert(not user or isinstance(user, string_types))
            assert(not pw or isinstance(pw, string_types))
            assert(not url or isinstance(url, string_types))
            assert(not certificate or isinstance(certificate, bytes))

        supported_auth_methods, _ = get_supported_methods(payloads, secure)
        for method in supported_auth_methods:
            if method.id in METHODS_KERBEROS:
                try:
                    return self._create_auth1_message_sspi(
                        url, method, user, pw, domain,
                        certificate=certificate
                    )

                except self._kerberos.GSSError as e:
                    self.logger.info(
                        'GSS error: method=%s error=%s (ignore)', method, e)

                except NotImplementedError:
                    self.logger.debug(
                        'Not supported conditions for method %s', method)

                except AuthenticationError as e:
                    self.logger.info(
                        'SSPI error: method=%s error=%s (ignore)', method, e)

                self._ctx = None

            elif user is None:
                continue

            elif method.id == METHOD_NTLM:
                self.logger.info(
                    'Fallback to py NTLM with creds: %s -> user=%s', url, user)
                return self._create_auth1_message_ntlm(domain, user, pw, certificate)

            elif method.id == METHOD_DIGEST:
                self.logger.info(
                    'Fallback to py Digest with creds: %s -> user=%s', url, user)
                return self._create_auth1_message_digest(domain, user, pw, method.args)

            elif method.id == METHOD_BASIC:
                self.logger.info(
                    'Fallback to py Basic with creds: %s -> user=%s', url, user)
                return self._create_auth1_message_basic(user, pw)

        if user is None:
            self.logger.info('No credentials found for URL=%s', url)

        raise AuthenticationError(
            'No acceptable auth found for: URL: %s', url)

    def create_auth2_message(self, payload):
        if self._sspi:
            return self._create_auth2_message_sspi(payload)
        elif self._method == METHOD_NTLM:
            return self._create_auth2_message_ntlm(payload)
        else:
            raise AuthenticationError(
                'Invalid state (expected method {})'.format(self._method)
            )
