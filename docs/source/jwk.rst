JSON Web Key (JWK)
==================

The jwk Module implements the `JSON Web Key`_ standard.
A JSON Web Key is represented by a JWK object, related utility classes and
functions are available in this module too.

.. _JSON Web Key: http://tools.ietf.org/html/rfc7517

Classes
-------

.. autoclass:: jwcrypto.jwk.JWK
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwk.JWKSet
   :members:
   :show-inheritance:

Exceptions
----------

.. autoclass:: jwcrypto.jwk.InvalidJWKType
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwk.InvalidJWKValue
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwk.InvalidJWKOperation
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwk.InvalidJWKUsage
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwk.RSAKeyMaterialError
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwk.RSAMaterialBoundsError
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwk.RSAMaterialConsistencyError
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwk.RSAMaterialRecoveryError
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jwk.RSAKeyValidationError
   :members:
   :show-inheritance:

Registries
----------

.. autodata:: jwcrypto.jwk.JWKTypesRegistry
   :annotation:

.. autodata:: jwcrypto.jwk.JWKValuesRegistry
   :annotation:

.. autodata:: jwcrypto.jwk.JWKParamsRegistry
   :annotation:

.. autodata:: jwcrypto.jwk.JWKEllipticCurveRegistry
   :annotation:

.. autodata:: jwcrypto.jwk.JWKUseRegistry
   :annotation:

.. autodata:: jwcrypto.jwk.JWKOperationsRegistry
   :annotation:

.. autodata:: jwcrypto.jwk.RSA_MIN_MODULUS_BITS
   :annotation:

.. autodata:: jwcrypto.jwk.RSA_MAX_MODULUS_BITS
   :annotation:

.. autodata:: jwcrypto.jwk.RSA_RECOVERY_DEADLINE_SECONDS
   :annotation:

Examples
--------

Create a 256bit symmetric key::
    >>> from jwcrypto import jwk
    >>> key = jwk.JWK.generate(kty='oct', size=256)

Export the key with::
    >>> key.export()    #doctest: +ELLIPSIS
    '{"k":"...","kty":"oct"}'

Create a 2048bit RSA key pair::
    >>> jwk.JWK.generate(kty='RSA', size=2048) #doctest: +ELLIPSIS
    {"kid":"Missing Key ID","thumbprint":"..."}

Create a P-256 EC key pair and export the public key::
    >>> key = jwk.JWK.generate(kty='EC', crv='P-256')
    >>> key.export(private_key=False)   #doctest: +ELLIPSIS
    '{"crv":"P-256","kty":"EC","x":"...","y":"..."}'

Import a P-256 Public Key::
    >>> expkey = {"y":"VYlYwBfOTIICojCPfdUjnmkpN-g-lzZKxzjAoFmDRm8",
    ...           "x":"3mdE0rODWRju6qqU01Kw5oPYdNxBOMisFvJFH1vEu9Q",
    ...           "crv":"P-256","kty":"EC"}
    >>> key = jwk.JWK(**expkey)

Import a Key from a PEM file::
    >>> with open("public.pem", "rb") as pemfile:  #doctest: +SKIP
    ...     key = jwk.JWK.from_pem(pemfile.read())

Complete a minimal RSA private JWK (only ``n``, ``e`` and ``d``) into a
fully validated key with its internal prime and CRT material recovered
through the bounded primitives of the installed cryptography library::
    >>> minimal = {"kty": "RSA", "n": n, "e": e, "d": d}  #doctest: +SKIP
    >>> key = jwk.JWK.from_rsa_private_material(minimal)  #doctest: +SKIP
    >>> key.thumbprint() == jwk.JWK(**full).thumbprint()  #doctest: +SKIP
    True

