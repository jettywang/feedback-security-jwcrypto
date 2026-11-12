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

Key Material and Cache Consistency
----------------------------------

A :class:`~jwcrypto.jwk.JWK` is a mutable mapping.  The object exposes an
explicit consistency contract between its current contents and the
operations allowed by :meth:`~jwcrypto.jwk.JWK.get_op_key`:

* The cryptography objects returned by ``get_op_key`` (and the key values
  used internally when signing, verifying, encrypting or decrypting) are
  derived from the type specific key parameters (``n``/``e``/``d``/... for
  RSA, ``x``/``y``/``d``/``crv`` for EC, ``x``/``d``/``crv`` for OKP,
  ``pub``/``priv`` plus ``alg`` for AKP, and ``k`` for oct).  These
  parameters are the *material* and are snapshotted when a key object is
  cached.  A cache entry is never used when the current material differs
  from the snapshot, including changes that bypass the overridden mapping
  methods.
* ``kid``, ``use``, ``key_ops``, ``alg`` for non-AKP keys and the X.509
  parameters (``x5u``, ``x5c``, ``x5t``, ``x5t#S256``) are *metadata* for
  this purpose.  Changing them keeps the cached cryptography objects, and
  the ``use``/``key_ops`` constraints are evaluated again on every
  ``get_op_key`` call.  Renaming a key via ``kid`` therefore does not
  disable normal use of the same public or private key.
* Changing or deleting material through ``[]``, attribute access,
  ``update``, ``|=``, ``setdefault``, ``del``, ``pop``, ``popitem``,
  ``clear`` or ``import_key`` invalidates the affected cached objects.
  A failed mutation (an invalid value rejected before assignment) leaves
  both the mapping and the cache untouched.
* Importing a new key replaces all contents and invalidates all cached
  objects, even if some parameter values happen to compare equal.
* If the key material needed for an operation is incomplete (for example
  the private exponent was deleted from an RSA key), ``get_op_key`` raises
  :class:`~jwcrypto.jwk.InvalidJWKType` instead of returning a stale key
  or a low-level ``TypeError``.  An explicitly empty ``key_ops`` list
  denies every operation.

The cache is populated lazily and rebuilding happens only after a material
change; metadata changes and read-only operations never force a rebuild.

Compatibility notes for this contract:

* Code that relied on ``dict.pop``/``popitem``/``clear`` or ``|=``
  silently replacing key material (and keeping the old cached key) will
  now see the new material used, or an error if the operation is not
  permitted.
* A ``key_ops`` list set explicitly to ``[]`` used to mean "no
  restriction"; it now denies every operation, matching the RFC 7517
  reading of an empty allow-list.  Remove the parameter instead of
  setting it to an empty list to allow all operations.
* Requesting private material from a public-only key (or material deleted
  from a private key) raises :class:`~jwcrypto.jwk.InvalidJWKType` instead
  of the previous low-level ``TypeError``/``NotImplementedError``.
  JWS/JWE helpers still wrap these errors in their usual verification
  and decryption exceptions.
* A rejected assignment (for example an invalid base64 value) leaves the
  existing cache usable; it does not force a rebuild.
* Rebuilding is lazy and per key: only the JWK whose material changed is
  affected, and only on its next cryptographic use.

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
