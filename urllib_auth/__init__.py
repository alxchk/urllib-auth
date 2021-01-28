from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__version__ = '1.2'


from .auth import (
    METHOD_NTLM, METHOD_NEGOTIATE,

    AuthenticationError, Authentication
)

from .HTTPAuthHandler import (
    HTTPAuthHandler, ProxyAuthHandler
)
