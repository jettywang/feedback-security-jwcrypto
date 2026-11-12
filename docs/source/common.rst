Common
======

Functions
---------
.. autofunction:: jwcrypto.common.base64url_encode
.. autofunction:: jwcrypto.common.base64url_decode
.. autofunction:: jwcrypto.common.json_encode
.. autofunction:: jwcrypto.common.json_decode

Classes
-------

.. autoclass:: jwcrypto.common.JWSEHeaderParameter

.. autoclass:: jwcrypto.common.JWSEHeaderRegistry
   :members:

Per-context extension policies
------------------------------

A ``JWSEHeaderRegistry`` is owned by one JWS or JWE object.  The
constructor copies the supplied parameters, and ``copy()`` returns an
independent snapshot, so updating one context's registry never changes
another context that was already created.

Extension handlers (``check_fn``) run only after the JWS signature or
the JWE authentication tag has been verified.  They must not rely on
values that appear only in an unprotected header; register an extension
whose handler needs authenticated input with ``mustprotect=True`` so the
unprotected occurrence is rejected while parsing.

Verification and decryption also accept an optional ``header_registry``
keyword argument to apply a policy snapshot to one call without mutating
the object::

    from jwcrypto import jwk, jws
    from jwcrypto.common import JWSEHeaderParameter

    def check_custom(jwobj):
        return jwobj.jose_header["custom1"] == "expected"

    policy_a = {"custom1": JWSEHeaderParameter(
        "Custom extension", True, True, check_custom)}

    verifier_a = jws.JWS(header_registry=policy_a)
    verifier_a.deserialize(token)
    verifier_a.verify(key)

    verifier_b = jws.JWS()          # no extension policy: token is rejected
    verifier_b.deserialize(token)
    verifier_b.verify(key)          # raises InvalidJWSSignature

    # A per-call policy is isolated and leaves the object unchanged.
    verifier_b.verify(key, header_registry=policy_a)

Standard parameter names (``alg``, ``enc``, ``crit``, ``b64``, ...) are
reserved: an extension cannot replace or delete them.  Unknown critical
headers, a handler that raises, and a handler that returns a false value
all cause an explicit verification failure.

Exceptions
----------

.. autoclass:: jwcrypto.common.JWException

.. autoclass:: jwcrypto.common.InvalidJWAAlgorithm
   :show-inheritance:

.. autoclass:: jwcrypto.common.InvalidCEKeyLength
   :show-inheritance:

.. autoclass:: jwcrypto.common.InvalidJWEOperation
   :show-inheritance:

.. autoclass:: jwcrypto.common.InvalidJWEKeyType
   :show-inheritance:

.. autoclass:: jwcrypto.common.InvalidJWEKeyLength
   :show-inheritance:

.. autoclass:: jwcrypto.common.InvalidJWSERegOperation
   :show-inheritance:

.. autoclass:: jwcrypto.common.JWKeyNotFound
   :show-inheritance:
