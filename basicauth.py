"""An incredibly simple HTTP basic auth implementation."""


from base64 import b64decode, b64encode

import sys
if sys.version_info >= (3, 0):
    from urllib.parse import quote, unquote
else:
    from urllib import quote, unquote


class DecodeError(Exception):
    pass


def encode(username, password):
    """Returns an HTTP basic authentication encrypted string given a valid
    username and password.
    """
    credentials = '{0}:{1}'.format(quote(username), quote(password)).\
        encode('latin1')
    return 'Basic {0}'.format(b64encode(credentials).decode('latin1'))


def decode(encoded_str):
    """Decode an encrypted HTTP basic authentication string. Returns a tuple of
    the form (username, password), and raises a DecodeError exception if
    nothing could be decoded.
    """
    split = encoded_str.strip().encode("latin1").split(None)

    # If split is only one element, try to decode the username and password
    # directly.
    if len(split) == 1:
        try:
            username, password = b64decode(split[0]).split(b':', 1)
        except:
            raise DecodeError

    # If there are only two elements, check the first and ensure it says
    # 'basic' so that we know we're about to decode the right thing. If not,
    # bail out.
    elif len(split) == 2:
        if split[0].strip().lower() == b'basic':
            try:
                username, password = b64decode(split[1]).split(b':', 1)
            except:
                raise DecodeError
        else:
            raise DecodeError

    # If there are more than 2 elements, something crazy must be happening.
    # Bail.
    else:
        raise DecodeError

    return (unquote(username.decode('latin1')),
            unquote(password.decode('latin1')))
