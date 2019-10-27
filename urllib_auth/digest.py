from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from string import ascii_lowercase
from collections import namedtuple
from hashlib import sha1, md5
from os import urandom

import sys

if sys.version_info.major > 2:
    from urllib.parse import urlparse
else:
    from urlparse import urlparse


DigestArgs = namedtuple(
    'DigestArgs', (
        'realm', 'nonce', 'algorithm', 'domain', 'qop'
    )
)


def parse_args(payload):
    args = []

    is_string = False
    is_quoted = False
    is_value = False
    is_value_first = False
    is_argument = False

    argument = None

    element = []

    for c in payload:
        if is_quoted:
            element.append(c)
            is_quoted = False

        elif is_value:
            if c == '"':
                if is_value_first:
                    is_string = True
                elif is_string:
                    is_string = False
                    is_value = False
                    is_value_first = False
                    value = ''.join(element)

                    args.append((argument, value))

                    argument = None
                    del element[:]
                else:
                    raise ValueError(
                        'Unexpected char <"> in non-string value'
                    )
            elif c == ',':
                if is_string:
                    element.append(c)
                else:
                    is_value = False
                    is_value_first = False
                    value = ''.join(element)

                    args.append((argument, value))
                    del element[:]
                    argument = None
            elif c == '\\':
                if is_string:
                    is_quoted = True
                else:
                    raise ValueError(
                        'Unexpected char <\\> in non-string value'
                    )
            else:
                element.append(c)

                if is_value_first:
                    is_value_first = False

        elif is_argument:
            if c == '=':
                is_argument = False
                is_value = True
                is_value_first = True
                argument = ''.join(element)
                del element[:]
            elif c in ascii_lowercase:
                element.append(c)
            else:
                raise ValueError(
                    'Unexpected char <{}> in argument'.format(c)
                )
        else:
            if c == ' ' or c == ',':
                continue
            elif c in ascii_lowercase:
                is_argument = True
                element.append(c)
            else:
                raise ValueError(
                    'Unexpected char <{}> outside anything'.format(c)
                )

    if element:
        if is_argument:
            raise ValueError(
                'Unexpected end of the sequence in argument'
            )
        elif is_quoted:
            raise ValueError(
                'Unexpected end of the sequence in quoted string value'
            )
        elif is_string:
            raise ValueError(
                'Unexpected end of the sequence in string value'
            )
        else:
            args.append((argument, ''.join(element)))

    return dict(args)



def make_hash(args):
    algorithm = args.get('algorithm', 'MD5')
    if algorithm == 'MD5':
        def _H(data):
            return md5(
                data if isinstance(data, bytes) else data.encode('ascii')
            ).hexdigest()

        def _KD(secret, data):
            return _H(':'.join((secret, data)))

        return algorithm, _H, _KD
    elif algorithm == 'SHA1':
        def _H(data):
            return sha1(
                data if isinstance(data, bytes) else data.encode('ascii')
            ).hexdigest()

        def _KD(secret, data):
            return _H(':'.join((secret, data)))

        return algorithm, _H, _KD
    else:
        raise ValueError('Unsupported algorithm {}'.format(algorithm))


def make_digest_response(domain, user, pw, args):
    if domain is not None:
        user = domain + '\\' + user

    parsed_args = parse_args(args.default)

    method = args.extra.get('method')
    if method is None:
        raise ValueError('Missing extra data: method')

    selector = args.extra.get('selector')
    if selector is None:
        raise ValueError('Missing extra data: selector')

    realm = parsed_args.get('realm')
    qop = parsed_args.get('qop')
    nonce = parsed_args.get('nonce')
    opaque = parsed_args.get('opaque')

    if nonce is None:
        raise ValueError('Missing data: nonce required')

    if realm is None:
        raise ValueError('Missing data: realm required')

    algorithm, H, KD = make_hash(parsed_args)

    A1 = ':'.join((user, realm, pw))
    A2 = ':'.join((method, selector))

    cnonce = md5(urandom(16)).hexdigest()[:16]

    if qop and qop in ('auth', 'auth-int'):
        digest = KD(H(A1), ':'.join((
            nonce, '00000001', cnonce, 'auth', H(A2)
        )))
    elif qop is None:
        digest = KD(H(A1), ':'.join((nonce, H(A2))))
    else:
        raise ValueError('Unsuppored qop: {}'.format(qop))

    values = [
        'username="{}"'.format(user),
        'realm="{}"'.format(realm),
        'nonce="{}"'.format(nonce),
        'uri="{}"'.format(selector),
        'response="{}"'.format(digest),
        'algorithm="{}"'.format(algorithm),
    ]

    if opaque:
        values.append(
            'opaque="{}"'.format(opaque)
        )

    if qop:
        values.extend([
            'qop=auth',
            'nc={}'.format('00000001'),
            'cnonce="{}"'.format(cnonce)
        ])

    return ', '.join(values)
