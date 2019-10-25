# This file is part of 'NTLM Authorization Proxy Server' http://sourceforge.net/projects/ntlmaps/
# Copyright 2001 Dmitry A. Rozmanov <dima@xenon.spb.ru>
#
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

from Crypto.Cipher import DES as _DES


if str == bytes:
    def as_char(x):
        return chr(x)
else:
    def as_char(x):
        return bytes((x,))


# ---------------------------------------------------------------------
class DES(object):

    __slots__ = ('cipher',)

    # -----------------------------------------------------------------
    def __init__(self, key_str):
        ""

        key_str = bytearray(key_str)

        k = str_to_key56(key_str)
        k = key56_to_key64(k)

        key_str = b''.join(as_char(c & 0xFF) for c in k)

        self.cipher = _DES.new(key_str, _DES.MODE_ECB)

    # -----------------------------------------------------------------
    def encrypt(self, plain_text):
        ""
        return self.cipher.encrypt(plain_text)

    # -----------------------------------------------------------------
    def decrypt(self, crypted_text):
        ""
        return self.cipher.decrypt(crypted_text)

# ---------------------------------------------------------------------
# Some Helpers
# ---------------------------------------------------------------------


DESException = 'DESException'

# ---------------------------------------------------------------------


def str_to_key56(key_str):
    ""
    if type(key_str) != type(''):
        # rise DESException, 'ERROR. Wrong key type.'
        pass
    if len(key_str) < 7:
        key_str = key_str + \
            b'\000\000\000\000\000\000\000'[:(7 - len(key_str))]
    key_56 = []
    for i in key_str[:7]:
        key_56.append(i)

    return key_56

# ---------------------------------------------------------------------


def key56_to_key64(key_56):
    ""
    key = []
    for i in range(8):
        key.append(0)

    key[0] = key_56[0]
    key[1] = ((key_56[0] << 7) & 0xFF) | (key_56[1] >> 1)
    key[2] = ((key_56[1] << 6) & 0xFF) | (key_56[2] >> 2)
    key[3] = ((key_56[2] << 5) & 0xFF) | (key_56[3] >> 3)
    key[4] = ((key_56[3] << 4) & 0xFF) | (key_56[4] >> 4)
    key[5] = ((key_56[4] << 3) & 0xFF) | (key_56[5] >> 5)
    key[6] = ((key_56[5] << 2) & 0xFF) | (key_56[6] >> 6)
    key[7] = (key_56[6] << 1) & 0xFF

    key = set_key_odd_parity(key)

    return key

# ---------------------------------------------------------------------


def set_key_odd_parity(key):
    ""
    for i in range(len(key)):
        for k in range(7):
            bit = 0
            t = key[i] >> k
            bit = (t ^ bit) & 0x1
        key[i] = (key[i] & 0xFE) | bit

    return key