# Copyright (C) 2015 JWCrypto Project Contributors - see LICENSE file

import copy
import json
from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections import namedtuple
from collections.abc import MutableMapping

# Padding stripping versions as described in
# RFC 7515 Appendix C


def base64url_encode(payload):
    if not isinstance(payload, bytes):
        payload = payload.encode('utf-8')
    encode = urlsafe_b64encode(payload)
    return encode.decode('utf-8').rstrip('=')


def base64url_decode(payload):
    size = len(payload) % 4
    if size == 2:
        payload += '=='
    elif size == 3:
        payload += '='
    elif size != 0:
        raise ValueError('Invalid base64 string')
    return urlsafe_b64decode(payload.encode('utf-8'))


# JSON encoding/decoding helpers with good defaults

def json_encode(string):
    if isinstance(string, bytes):
        string = string.decode('utf-8')
    return json.dumps(string, separators=(',', ':'), sort_keys=True)


def json_decode(string):
    if isinstance(string, bytes):
        string = string.decode('utf-8')
    return json.loads(string)


class JWException(Exception):
    pass


class InvalidJWAAlgorithm(JWException):
    def __init__(self, message=None):
        msg = 'Invalid JWA Algorithm name'
        if message:
            msg += ' (%s)' % message
        super(InvalidJWAAlgorithm, self).__init__(msg)


class InvalidCEKeyLength(JWException):
    """Invalid CEK Key Length.

    This exception is raised when a Content Encryption Key does not match
    the required length.
    """

    def __init__(self, expected, obtained):
        msg = 'Expected key of length %d bits, got %d' % (expected, obtained)
        super(InvalidCEKeyLength, self).__init__(msg)


class InvalidJWEData(JWException):
    """Invalid JWE Object.

    This exception is raised when the JWE Object is invalid and/or
    improperly formatted.
    """

    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = message
        else:
            msg = 'Unknown Data Verification Failure'
        if exception:
            msg += ' {%s}' % str(exception)
        super(InvalidJWEData, self).__init__(msg)


class InvalidJWSEHeader(JWException):
    """Invalid JWSE Header.

    This exception is raised when a JWS or JWE Header is invalid and/or
    improperly formatted.
    """

    def __init__(self, message=None, exception=None):
        msg = message if message else 'Unknown Header Verification Failure'
        if exception:
            msg += ' {%s}' % str(exception)
        super(InvalidJWSEHeader, self).__init__(msg)


class InvalidJWEOperation(JWException):
    """Invalid JWS Object.

    This exception is raised when a requested operation cannot
    be execute due to unsatisfied conditions.
    """

    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = message
        else:
            msg = 'Unknown Operation Failure'
        if exception:
            msg += ' {%s}' % repr(exception)
        super(InvalidJWEOperation, self).__init__(msg)


class InvalidJWEKeyType(JWException):
    """Invalid JWE Key Type.

    This exception is raised when the provided JWK Key does not match
    the type required by the specified algorithm.
    """

    def __init__(self, expected, obtained):
        msg = 'Expected key type %s, got %s' % (expected, obtained)
        super(InvalidJWEKeyType, self).__init__(msg)


class InvalidJWEKeyLength(JWException):
    """Invalid JWE Key Length.

    This exception is raised when the provided JWK Key does not match
    the length required by the specified algorithm.
    """

    def __init__(self, expected, obtained):
        msg = 'Expected key of length %d, got %d' % (expected, obtained)
        super(InvalidJWEKeyLength, self).__init__(msg)


class InvalidJWSERegOperation(JWException):
    """Invalid JWSE Header Registry Operation.

    This exception is raised when there is an error in trying to add a JW
    Signature or Encryption header to the Registry.
    """

    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = message
        else:
            msg = 'Unknown Operation Failure'
        if exception:
            msg += ' {%s}' % repr(exception)
        super(InvalidJWSERegOperation, self).__init__(msg)


class JWKeyNotFound(JWException):
    """The key needed to complete the operation was not found.

    This exception is raised when a JWKSet is used to perform
    some operation and the key required to successfully complete
    the operation is not found.
    """

    def __init__(self, message=None):
        if message:
            msg = message
        else:
            msg = 'Key Not Found'
        super(JWKeyNotFound, self).__init__(msg)


# JWSE Header Registry definitions

# RFC 7515 - 9.1: JSON Web Signature and Encryption Header Parameters Registry
# HeaderParameters are for both JWS and JWE
JWSEHeaderParameter = namedtuple('Parameter',
                                 'description mustprotect supported check_fn')

STANDARD_HEADER_NAMES = frozenset((
    'alg', 'enc', 'zip', 'jku', 'jwk', 'kid', 'x5u', 'x5c', 'x5t',
    'x5t#S256', 'typ', 'cty', 'crit', 'b64',
))
"""Names defined by JWS/JWE standards.

A registry built from a protocol's standard registry (as JWS/JWE do) treats
all of these names as reserved: an application extension cannot silently
replace the meaning of a standard parameter.  Standalone registries may
describe a narrower custom namespace.
"""


class JWSEHeaderRegistry(MutableMapping):
    """A per-context registry of JOSE header parameters.

    A registry instance is owned by one JWS or JWE object.  The constructor
    takes a snapshot of the supplied parameters, so later changes to the
    source mapping (or to another context's registry) are never observed by
    an already-created context.  Use :meth:`copy` when an independent policy
    snapshot is needed for a single verification operation.

    Names of standard JWS/JWE parameters are reserved: they cannot be
    deleted or replaced by an application extension.  Extension headers may
    be replaced, but only by a parameter that does not weaken
    ``mustprotect``.
    """

    def __init__(self, init_registry=None):
        if init_registry is not None:
            if isinstance(init_registry, JWSEHeaderRegistry):
                self._registry = copy.deepcopy(init_registry._registry)
                self._reserved = set(init_registry._reserved)
            elif isinstance(init_registry, dict):
                self._registry = copy.deepcopy(init_registry)
                self._reserved = set(init_registry) & STANDARD_HEADER_NAMES
            else:
                raise InvalidJWSERegOperation('Unknown input type')
        else:
            self._registry = {}
            self._reserved = set()

        MutableMapping.__init__(self)

    def copy(self):
        """Return an independent copy of this registry.

        The copy has the same parameter snapshots, so mutating it cannot
        affect the original registry or any context using it.
        """
        new = JWSEHeaderRegistry()
        new._registry = copy.deepcopy(self._registry)
        new._reserved = set(self._reserved)
        return new

    def reserve(self, names):
        """Mark header names as reserved in this context.

        The JWS and JWE objects use this to reserve all standard parameter
        names, including names that belong to the sibling protocol, so an
        extension cannot silently take over their meaning.
        """
        self._reserved.update(names)

    def check_header(self, h, value):
        if h not in self._registry:
            raise InvalidJWSERegOperation('No header "%s" found in registry'
                                          % h)

        param = self._registry[h]
        if param.check_fn is None:
            return True
        else:
            return param.check_fn(value)

    def __getitem__(self, key):
        return self._registry.__getitem__(key)

    def __iter__(self):
        return self._registry.__iter__()

    def __delitem__(self, key):
        if key in self._reserved:
            raise InvalidJWSERegOperation(
                'Unable to delete standard header "%s"' % key)
        if self._registry[key].mustprotect or \
           self._registry[key].supported:
            raise InvalidJWSERegOperation('Unable to delete protected or '
                                          'supported field')
        else:
            self._registry.__delitem__(key)

    def __setitem__(self, h, jwse_header_param):
        if h in self._reserved:
            raise InvalidJWSERegOperation(
                'Unable to override standard header "%s"' % h)
        if not isinstance(jwse_header_param, JWSEHeaderParameter):
            raise InvalidJWSERegOperation(
                'Invalid parameter for header "%s"' % h)

        if h in self._registry:
            p = self._registry[h]
            if p.mustprotect and not jwse_header_param.mustprotect:
                raise InvalidJWSERegOperation(
                    'Header "%s" must remain protected' % h)

        self._registry[h] = jwse_header_param

    def __len__(self):
        return self._registry.__len__()


def merge_headers(protected, *unprotected, registry=None):
    """Merges protected and unprotected headers and checks for duplicates.

    :param protected: A dict representing the protected header (or None).
    :param unprotected: One or more dicts representing unprotected headers.
    :param registry: Optional JWSEHeaderRegistry to enforce 'mustprotect'.

    :raises InvalidJWSEHeader: If duplicate keys are found or an unprotected
        header contains a parameter that must be protected.
    :return: A dictionary with the merged headers.
    """
    merged = dict(protected) if protected is not None else {}

    for uh in unprotected:
        if uh is None:
            continue
        for h in list(uh.keys()):
            if registry and h in registry and registry[h].mustprotect:
                raise InvalidJWSEHeader('"%s" must be protected' % h)
            if h in merged:
                raise InvalidJWSEHeader('Duplicate header: "%s"' % h)
            merged[h] = uh[h]

    return merged


def check_crit(merged, protected, registry=None,
               require_protected_values=False):
    """Validates the 'crit' header according to RFC 7515 / RFC 7516.

    This performs only structural validation.  It never invokes extension
    handlers: callers MUST run it while parsing headers and MUST run
    :func:`validate_headers` with the same registry only after the
    cryptographic operation (signature or tag verification) succeeded.

    An extension whose handler needs authenticated data MUST be registered
    with ``mustprotect=True``.  Protocol verification paths additionally
    pass ``require_protected_values=True``, which requires every parameter
    named in ``crit`` to be present in the protected header, because only
    that header is covered by the JWS signature or JWE AAD.

    :param merged: A dict with the merged headers.
    :param protected: The protected header dict (or None).
    :param registry: Optional JWSEHeaderRegistry to check support.
    :param require_protected_values: Require each critical parameter value
        itself to be in the protected header.

    :raises InvalidJWSEHeader: for an empty or malformed "crit", an
        unprotected "crit", an unknown or unsupported critical parameter,
        a missing critical parameter, or (when enabled) a critical
        parameter that is not protected.
    """
    if merged is None:
        return

    if 'crit' not in merged:
        return
    crit = merged['crit']

    if not isinstance(crit, list) or len(crit) == 0:
        raise InvalidJWSEHeader('"crit" header must be a non-empty list')

    if protected is None or 'crit' not in protected:
        raise InvalidJWSEHeader('"crit" must be protected')

    for k in crit:
        if not isinstance(k, str):
            raise InvalidJWSEHeader('Critical header name must be a string')
        if registry is not None:
            if k not in registry:
                raise InvalidJWSEHeader('Unknown critical header: "%s"' % k)
            if not registry[k].supported:
                raise InvalidJWSEHeader(
                    'Unsupported critical header: "%s"' % k)
        if require_protected_values and k not in protected:
            raise InvalidJWSEHeader(
                'Critical header "%s" must be protected' % k)
        if k not in merged:
            raise InvalidJWSEHeader('Missing critical header "%s"' % k)


def validate_headers(merged, registry=None, target=None, run_handlers=True):
    """Run header handlers, rejecting failures explicitly.

    This MUST be called with ``run_handlers=True`` only after the token's
    cryptographic operation succeeded.  The handlers may then consult values
    that are covered by the signature or authenticated encryption, but they
    MUST NOT treat values that only appeared in an unprotected header as
    authenticated (register a handler whose input needs authentication with
    ``mustprotect=True``).

    An exception raised by a handler is converted to
    :class:`InvalidJWSEHeader`; a handler returning anything other than a
    truthy value is also rejected.  This gives callers a single explicit
    failure semantic for extension processing.

    ``run_handlers=False`` performs only the built-in structural checks
    (currently the ``b64`` type check) and deliberately does not call any
    registered extension handler.

    :param merged: A dict with the merged headers.
    :param registry: Optional JWSEHeaderRegistry instance.
    :param target: Optional target object (JWS or JWE instance) passed
                   to check_header.
    :param run_handlers: Whether to invoke registered handler callbacks.

    :raises InvalidJWSEHeader: if a handler fails or cannot be found.
    """
    if merged is None:
        return

    if 'b64' in merged and not isinstance(merged['b64'], bool):
        raise InvalidJWSEHeader('b64 header must be a boolean')

    if registry is not None and run_handlers:
        for hdr in merged:
            if hdr in registry:
                try:
                    result = registry.check_header(hdr, target)
                except InvalidJWSEHeader:
                    raise
                except Exception as e:  # pylint: disable=broad-except
                    raise InvalidJWSEHeader(
                        'Header handler failed for "%s"' % hdr) from e
                if not result:
                    raise InvalidJWSEHeader(
                        'Failed header check for "%s"' % hdr)


def merge_and_check_headers(protected, *unprotected, registry=None,
                            target=None, run_handlers=True):
    """Merge headers, run structural checks and optionally header handlers.

    This helper is not part of the JWS/JWE verification path.  Callers that
    pass ``run_handlers=True`` must have already completed the cryptographic
    verification for the token whose headers are being passed in.
    """
    merged = merge_headers(protected, *unprotected, registry=registry)
    check_crit(merged, protected=protected, registry=registry)
    validate_headers(merged, registry=registry, target=target,
                     run_handlers=run_handlers)
    return merged
