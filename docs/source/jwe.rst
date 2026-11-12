JSON Web Encryption (JWE)
=========================

The jwe Module implements the `JSON Web Encryption`_ standard.
A JSON Web Encryption is represented by a JWE object, related utility
classes and functions are available in this module too.

.. _JSON Web Encryption: https://tools.ietf.org/html/rfc7516

Classes
-------

.. autoclass:: jwcrypto.jwe.JWE
   :members:
   :show-inheritance:

Variables
---------

.. autodata:: jwcrypto.jwe.default_allowed_algs

.. autodata:: jwcrypto.jwa.default_pbes2_decrypt_budget
   :annotation:

Exceptions
----------

.. autoclass:: jwcrypto.jwe.InvalidJWEOperation
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwe.InvalidJWEData
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwe.InvalidJWEPBES2Parameters
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwe.JWEPBES2BudgetExceeded
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwe.InvalidJWEKeyType
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwe.InvalidJWEKeyLength
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwe.InvalidCEKeyLength
   :members:
   :show-inheritance:

Registries
----------

.. autodata:: jwcrypto.jwe.JWEHeaderRegistry
   :annotation:

Examples
--------

Symmetric keys
~~~~~~~~~~~~~~

Encrypt a JWE token::
    >>> from jwcrypto import jwk, jwe
    >>> from jwcrypto.common import json_encode
    >>> key = jwk.JWK.generate(kty='oct', size=256)
    >>> payload = "My Encrypted message"
    >>> jwetoken = jwe.JWE(payload.encode('utf-8'),
    ...                    json_encode({"alg": "A256KW",
    ...                                 "enc": "A256CBC-HS512"}))
    >>> jwetoken.add_recipient(key)
    >>> enc = jwetoken.serialize()

Decrypt a JWE token::
    >>> jwetoken = jwe.JWE()
    >>> jwetoken.deserialize(enc)
    >>> jwetoken.decrypt(key)
    >>> payload = jwetoken.payload

Asymmetric keys
~~~~~~~~~~~~~~~

Encrypt a JWE token::
    >>> from jwcrypto import jwk, jwe
    >>> from jwcrypto.common import json_encode, json_decode
    >>> public_key = jwk.JWK()
    >>> private_key = jwk.JWK.generate(kty='RSA', size=2048)
    >>> public_key.import_key(**json_decode(private_key.export_public()))
    >>> payload = "My Encrypted message"
    >>> protected_header = {
    ...     "alg": "RSA-OAEP-256",
    ...     "enc": "A256CBC-HS512",
    ...     "typ": "JWE",
    ...     "kid": public_key.thumbprint(),
    ... }
    >>> jwetoken = jwe.JWE(payload.encode('utf-8'),
    ...                    recipient=public_key,
    ...                    protected=protected_header)
    >>> enc = jwetoken.serialize()

Decrypt a JWE token::
    >>> jwetoken = jwe.JWE()
    >>> jwetoken.deserialize(enc, key=private_key)
    >>> payload = jwetoken.payload

PBES2 call budget
~~~~~~~~~~~~~~~~~

PBES2 key derivation is intentionally expensive.  A single JWE may carry
several recipients and a JWKSet may offer many candidate keys, so the
number of derivations is not bounded by the per-token ``p2c`` parameter
alone.  :meth:`jwcrypto.jwe.JWE.decrypt` accepts a call-level budget that
is shared by every attempt in that call and checked before each
derivation::

    from jwcrypto import jwk
    password = jwk.JWK.from_password('a password')
    jwetoken = jwe.JWE()
    jwetoken.deserialize(enc)
    jwetoken.decrypt(password, max_pbes2_iterations=300000)
    jwetoken.payload

The budget defaults to :data:`jwcrypto.jwa.default_pbes2_decrypt_budget`,
is recreated for every call, and never inherits unused credit from an
earlier attempt.  Malformed PBES2 parameters raise
:class:`jwcrypto.jwe.InvalidJWEPBES2Parameters`, an exhausted budget
raises :class:`jwcrypto.jwe.JWEPBES2BudgetExceeded`, and a well-formed
token that simply does not match the supplied password keeps raising
:class:`jwcrypto.jwe.InvalidJWEData`.
