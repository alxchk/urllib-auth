__all__ = (
    'METHOD_NTLM', 'METHOD_NEGOTIATE', 'METHOD_KERBEROS',
    'KerberosBackend',
    'AuthenticationError', 'Authentication',
    'get_supported_methods'
)

import urlparse
import hashlib

from .ntlm import (
    NTLM_TYPE1_FLAGS,

    NTLM_NegotiateOemDomainSupplied,
    create_NTLM_NEGOTIATE_MESSAGE,
    parse_NTLM_CHALLENGE_MESSAGE,
    create_NTLM_AUTHENTICATE_MESSAGE
)

METHOD_NTLM = 'NTLM'
METHOD_NEGOTIATE = 'Negotiate'
METHOD_KERBEROS = 'Kerberos'

METHODS_PRIORITY = (
    METHOD_NEGOTIATE, METHOD_NTLM, METHOD_KERBEROS
)


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
            self.kerberos = __import__('winkerberos')
            self.has_sspi_ntlm_support = True
            self.has_sspi_nego_support = True

        except ImportError:
            try:
                self.kerberos = __import__('kerberos')

                self.has_gssapi_support = True

            except ImportError:
                self.kerberos = None

    def __getattr__(self, attr):
        if self.kerberos:
            return getattr(self.kerberos, attr)


def _get_method(method):
    for known_method in (METHOD_NTLM, METHOD_NEGOTIATE):
        if method.lower() == known_method.lower():
            return known_method


def get_supported_methods(methods):
    methods = set(
        method for method in [
            _get_method(method) for method in methods
        ] if method is not None
    )

    return [
        method for method in METHODS_PRIORITY if method in methods
    ], [
        method for method in methods if method not in METHODS_PRIORITY
    ]


class AuthenticationError(Exception):
    pass


class Authentication(object):
    __slots__ = (
        'logger',
        '_ctx', '_method',

        '_channel_bindings',

        '_ntlm_user', '_ntlm_domain', '_ntlm_password',
        '_kerberos'
    )

    def __init__(self, logger):
        self.logger = logger
        self._ctx = None
        self._method = None
        self._ntlm_user = None
        self._ntlm_domain = None
        self._ntlm_password = None
        self._channel_bindings = None
        self._kerberos = KerberosBackend()

    def _create_auth1_message_sspi(
            self, url, method, user=None,
            password=None, domain=None, flags=0,
            certificate=None):

        server = None
        principal = None

        kwargs = {
            'user': user,
            'password': password,
            'domain': domain,
            'gssflags': flags
        }

        parsed = urlparse.urlparse(url)
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
                mech_oid = self._kerberosGSS_MECH_OID_KRB5

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

                if user and domain:
                    principal = user + '@' + domain

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

        except TypeError:
            if password:
                raise NotImplementedError(
                    "ccs-kerberos doesn't support password auth")

            del kwargs['password']
            result, self._ctx = self._kerberos.authGSSClientInit(
                server, principal, **kwargs
            )

        if result < 0:
            self.logger.error('GSSAPI: authGSSClientInit Result: %d', result)
            raise AuthenticationError(result)

        self.logger.debug(
            'GSSAPI: New context for SPN=%s%s', server,
            '' if not principal else 'Principal='+principal
        )

        if need_inquire_cred:
            result = self._kerberos.authGSSClientInquireCred(self._ctx)
            if result < 0:
                raise AuthenticationError(result)

            self.logger.warning(
                'GSSAPI: Using principal: %s',
                self._kerberos.authGSSClientUserName(self._ctx)
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
        return result, method, self._kerberos.authGSSClientResponse(self._ctx)

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

        return result == self._kerberos.CONTINUE, self._method, payload

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

    def create_auth1_message(self, domain, user, pw, url, auth_methods, certificate):
        supported_auth_methods, _ = get_supported_methods(auth_methods)
        for method in supported_auth_methods:
            try:
                return self._create_auth1_message_sspi(
                    url, method, user, pw, domain,
                    certificate=certificate
                )

            except NotImplementedError:
                self.logger.debug(
                    'Not supported conditions for method %s', method)

            except AuthenticationError as e:
                self.logger.info(
                    'SSPI error: method=%s error=%s (ignore)', method, e)

        self.logger.debug(
            'No usable SSPI/GSSAPI auth method found for URL=%s', url)

        if user is None:
            self.logger.info('No credentials found for URL=%s', url)

        if METHOD_NTLM not in auth_methods or not user:
            raise AuthenticationError(
                'No acceptable auth found for: URL: %s', url)

        self.logger.info(
            'Fallback to py NTLM with creds: %s -> user=%s', url, user)

        type1_flags = NTLM_TYPE1_FLAGS
        if domain is None:
            domain = ''
            type1_flags &= ~NTLM_NegotiateOemDomainSupplied

        self._method = METHOD_NTLM
        self._ntlm_user = user
        self._ntlm_password = pw
        self._ntlm_domain = domain

        return True, self._method, create_NTLM_NEGOTIATE_MESSAGE(
            user, type1_flags)

    def create_auth2_message(self, payload):
        if self._ctx:
            return self._create_auth2_message_sspi(payload)

        if self._method != METHOD_NTLM:
            raise AuthenticationError('Invalid state (expected method NTLM)')

        ServerChallenge, NegotiateFlags = parse_NTLM_CHALLENGE_MESSAGE(payload)
        return True, self._method, create_NTLM_AUTHENTICATE_MESSAGE(
            ServerChallenge,
            self._ntlm_user, self._ntlm_domain, self._ntlm_password,
            NegotiateFlags
        )
