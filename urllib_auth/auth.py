import urlparse

from .ntlm import (
    NTLM_TYPE1_FLAGS,
    
    NTLM_NegotiateOemDomainSupplied,
    create_NTLM_NEGOTIATE_MESSAGE,
    parse_NTLM_CHALLENGE_MESSAGE,
    create_NTLM_AUTHENTICATE_MESSAGE
)

has_gssapi_support = False
has_sspi_ntlm_support = False
has_sspi_nego_support = False

try:
    import winkerberos as kerberos

    has_sspi_ntlm_support = True
    has_sspi_nego_support = True

    CONTINUE = kerberos.AUTH_GSS_CONTINUE
except ImportError:

    try:
        import kerberos

        has_gssapi_support = True
        CONTINUE = kerberos.AUTH_GSS_CONTINUE
    except ImportError:
        CONTINUE = 1


METHOD_NTLM = 'NTLM'
METHOD_NEGOTIATE = 'Negotiate'


class AuthenticationError(Exception):
    pass


class Authentication(object):
    __slots__ = (
        'logger',
        '_ctx', '_method',

        '_ntlm_user', '_ntlm_domain', '_ntlm_password',
    )

    def __init__(self, logger):
        self.logger = logger
        self._ctx = None
        self._method = None
        self._ntlm_user = None
        self._ntlm_domain = None
        self._ntlm_password = None

    def _create_auth1_message_sspi(
            self, url, method, user=None,
            password=None, domain=None, flags=0):

        method = method.upper()
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
        domain = host.rsplit(':', 1)[0]

        if scheme.startswith('HTTP'):
            service = 'HTTP'
        else:
            service = scheme

        use_gssapi = False

        if has_sspi_nego_support and method == METHOD_NEGOTIATE.upper():
            kwargs['mech_oid'] = kerberos.GSS_MECH_OID_SPNEGO
            method = METHOD_NEGOTIATE
            server = service + '@' + domain

        elif has_sspi_ntlm_support and method == METHOD_NTLM.upper():
            # This is only for SSPI
            kwargs['mech_oid'] = kerberos.GSS_MECH_OID_NTLM
            method = METHOD_NTLM
            server = domain

        elif has_gssapi_support and method == METHOD_NEGOTIATE.upper():
            server = service + '@' + domain
            kwargs['mech_oid'] = kerberos.GSS_MECH_OID_SPNEGO

            if password:
                raise NotImplementedError(
                    "ccs-kerberos doesn't support password auth")

            if user and domain:
                principal = user + '@' + domain

            del kwargs['user']
            del kwargs['password']
            del kwargs['domain']

            use_gssapi = True

        else:
            raise NotImplementedError('No supported auth methods')

        result, self._ctx = kerberos.authGSSClientInit(
            server, principal, **kwargs
        )

        if result < 0:
            self.logger.error('GSSAPI: authGSSClientInit Result: %d', result)
            raise AuthenticationError(result)

        if use_gssapi:
            result = kerberos.authGSSClientInquireCred(self._ctx)
            if result < 0:
                raise AuthenticationError(result)

            self.logger.warning(
                'GSSAPI: Using principal: %s',
                kerberos.authGSSClientUserName(self._ctx)
            )

        result = kerberos.authGSSClientStep(self._ctx, '')
        if result < 0:
            self.logger.error('GSSAPI: authGSSClientInit Result: %d', result)
            raise AuthenticationError(result)

        self._method = method
        return result, method, kerberos.authGSSClientResponse(self._ctx)

    def _create_auth2_message_sspi(self, payload):
        result = kerberos.authGSSClientStep(self._ctx, payload)

        if result < 0:
            self.logger.error('GSSAPI: authGSSClientStep (2) Result: %d', result)
            raise AuthenticationError(result)
        
        return result, self._method, kerberos.authGSSClientResponse(self._ctx)

    def create_auth1_message(self, domain, user, pw, url, auth_methods):
        for method in auth_methods:
            try:
                return self._create_auth1_message_sspi(
                    url, method, user, pw, domain,

                )

            except NotImplementedError:
                pass

            except AuthenticationError as e:
                self.logger.info('SSPI error: %s (ignore)', e)

        if not user:
            self.logger.warning(
                'No login/password found for: URL: %s (%s)', url, e)

        if 'NTLM' not in auth_methods or not user:
            raise AuthenticationError('No acceptable auth found for: URL: %s', url)
    
        self.logger.info('Fallback to py NTLM with creds: %s -> user=%s', url, user)

        type1_flags = NTLM_TYPE1_FLAGS
        if domain is None:
            domain = ''
            type1_flags &= ~NTLM_NegotiateOemDomainSupplied

        self._method = METHOD_NTLM
        self._ntlm_user = user
        self._ntlm_password = pw
        self._ntlm_domain = domain

        return CONTINUE, self._method, create_NTLM_NEGOTIATE_MESSAGE(
            user, type1_flags)

    def create_auth2_message(self, payload):
        if self._ctx:
            return self._create_auth2_message_sspi(payload)    
        
        if self._method != METHOD_NTLM:
            raise AuthenticationError('Invalid state (expected method NTLM)')
        
        ServerChallenge, NegotiateFlags = parse_NTLM_CHALLENGE_MESSAGE(payload)
        return 0, self._method, create_NTLM_AUTHENTICATE_MESSAGE(
            ServerChallenge,
            self._ntlm_user, self._ntlm_domain, self._ntlm_password,
            NegotiateFlags
        )