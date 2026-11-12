# Copyright (C) 2015 JWCrypto Project Contributors - see LICENSE file

import copy
import zlib

from jwcrypto import common
from jwcrypto.common import InvalidJWSEHeader
from jwcrypto.common import JWKeyNotFound
from jwcrypto.common import JWSEHeaderParameter, JWSEHeaderRegistry
from jwcrypto.common import base64url_decode, base64url_encode
from jwcrypto.common import check_crit, merge_headers, validate_headers
from jwcrypto.common import json_decode, json_encode
from jwcrypto.jwa import JWA
from jwcrypto.jwk import JWKSet

# Limit the amount of data we are willing to decompress by default.
default_max_compressed_size = 256 * 1024
# Limit the maximum plaintext size to 100MB by default.
default_max_plaintext_size = 100 * 1024 * 1024
# Limit the number of recipients accepted in one decrypt() call.
default_max_recipients = 10

# RFC 7516 - 4.1
# name: (description, supported?)
JWEHeaderRegistry = {
    'alg': JWSEHeaderParameter('Algorithm', False, True, None),
    'enc': JWSEHeaderParameter('Encryption Algorithm', False, True, None),
    'zip': JWSEHeaderParameter('Compression Algorithm', True, True, None),
    'jku': JWSEHeaderParameter('JWK Set URL', False, False, None),
    'jwk': JWSEHeaderParameter('JSON Web Key', False, False, None),
    'kid': JWSEHeaderParameter('Key ID', False, True, None),
    'x5u': JWSEHeaderParameter('X.509 URL', False, False, None),
    'x5c': JWSEHeaderParameter('X.509 Certificate Chain', False, False, None),
    'x5t': JWSEHeaderParameter('X.509 Certificate SHA-1 Thumbprint', False,
                               False, None),
    'x5t#S256': JWSEHeaderParameter('X.509 Certificate SHA-256 Thumbprint',
                                    False, False, None),
    'typ': JWSEHeaderParameter('Type', False, True, None),
    'cty': JWSEHeaderParameter('Content Type', False, True, None),
    'crit': JWSEHeaderParameter('Critical', True, True, None),
}
"""Registry of valid header parameters"""

default_allowed_algs = [
    # Key Management Algorithms
    'RSA-OAEP', 'RSA-OAEP-256',
    'A128KW', 'A192KW', 'A256KW',
    'dir',
    'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
    'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
    'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
    # Content Encryption Algorithms
    'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512',
    'A128GCM', 'A192GCM', 'A256GCM']
"""Default allowed algorithms"""

# Key management algorithms that generate a CEK which can be reused when
# re-wrapping the same content under a new recipient key.  Algorithms that
# derive the CEK from the recipient key ('dir' and bare 'ECDH-ES') cannot
# be used because the content ciphertext is bound to the original CEK.
# RSA1_5 is deliberately excluded as it is prohibited by RFC 7516 and is not
# part of the default allowed algorithms.
rekey_keymgmt_algs = [
    'RSA-OAEP', 'RSA-OAEP-256',
    'A128KW', 'A192KW', 'A256KW',
    'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
    'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
    'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
]
"""Key management algorithms usable for recipient re-keying.

These algorithms wrap an existing CEK and therefore allow the protected
header, AAD, IV, ciphertext and tag of an already authenticated token to be
preserved byte-for-byte.  'dir' and bare 'ECDH-ES' are intentionally absent:
they derive the CEK from the recipient key and cannot reuse an existing one.
"""


def _rekey_alg_error(name):
    if name == 'dir':
        return ('"dir" derives the content encryption key from the recipient '
                'key and cannot reuse an existing CEK')
    if name == 'ECDH-ES':
        return ('"ECDH-ES" derives the content encryption key from the '
                'recipient key and cannot reuse an existing CEK')
    if name == 'RSA1_5':
        return ('"RSA1_5" is a prohibited key management algorithm and is '
                'not supported for re-keying')
    return '"%s" cannot reuse an existing CEK for re-keying' % name


# These have been moved to jwcrypto.common, maintain here for backwards compat
InvalidCEKeyLength = common.InvalidCEKeyLength
InvalidJWEData = common.InvalidJWEData
InvalidJWEKeyLength = common.InvalidJWEKeyLength
InvalidJWEKeyType = common.InvalidJWEKeyType
InvalidJWEOperation = common.InvalidJWEOperation


class JWE:
    """JSON Web Encryption object

    This object represent a JWE token.
    """

    def __init__(self, plaintext=None, protected=None, unprotected=None,
                 aad=None, algs=None, recipient=None, header=None,
                 header_registry=None, flattened=True):
        """Creates a JWE token.

        :param plaintext(bytes): An arbitrary plaintext to be encrypted.
        :param protected: A JSON string with the protected header.
        :param unprotected: A JSON string with the shared unprotected header.
        :param aad(bytes): Arbitrary additional authenticated data
        :param algs: An optional list of allowed algorithms
        :param recipient: An optional, default recipient key
        :param header: An optional header for the default recipient
        :param header_registry: Optional additions to the header registry
        :param flattened: Use flattened serialization syntax (default True)
        """
        self._allowed_algs = None
        self.objects = {}
        self.plaintext = None
        self.header_registry = JWSEHeaderRegistry(JWEHeaderRegistry)
        self.flattened = flattened
        if header_registry:
            self.header_registry.update(header_registry)
        if plaintext is not None:
            if isinstance(plaintext, bytes):
                self.plaintext = plaintext
            else:
                self.plaintext = plaintext.encode('utf-8')
        self.cek = None
        self.decryptlog = None
        if aad:
            self.objects['aad'] = aad
        if protected:
            if isinstance(protected, dict):
                protected = json_encode(protected)
            else:
                json_decode(protected)  # check header encoding
            self.objects['protected'] = protected
        if unprotected:
            if isinstance(unprotected, dict):
                unprotected = json_encode(unprotected)
            else:
                json_decode(unprotected)  # check header encoding
            self.objects['unprotected'] = unprotected
        if algs:
            self._allowed_algs = algs

        if recipient:
            self.add_recipient(recipient, header=header)
        elif header:
            raise ValueError('Header is allowed only with default recipient')

    def _jwa_keymgmt(self, name):
        allowed = self._allowed_algs or default_allowed_algs
        if name not in allowed:
            raise InvalidJWEOperation('Algorithm not allowed')
        return JWA.keymgmt_alg(name)

    def _jwa_enc(self, name):
        allowed = self._allowed_algs or default_allowed_algs
        if name not in allowed:
            raise InvalidJWEOperation('Algorithm not allowed')
        return JWA.encryption_alg(name)

    @property
    def allowed_algs(self):
        """Allowed algorithms.

        The list of allowed algorithms.
        Can be changed by setting a list of algorithm names.
        """

        if self._allowed_algs:
            return self._allowed_algs
        else:
            return default_allowed_algs

    @allowed_algs.setter
    def allowed_algs(self, algs):
        if not isinstance(algs, list):
            raise TypeError('Allowed Algs must be a list')
        self._allowed_algs = algs

    def _merge_headers(self, h1, h2):
        try:
            return merge_headers(h1, h2)
        except InvalidJWSEHeader as e:
            raise InvalidJWEData(str(e)) from e

    def _get_jose_header(self, header=None):
        ph = json_decode(self.objects.get('protected', '{}'))
        uh = json_decode(self.objects.get('unprotected', '{}'))
        rh = None
        if header:
            if isinstance(header, dict):
                rh = header
            else:
                rh = json_decode(header)
        try:
            jh = merge_headers(ph, uh, rh, registry=self.header_registry)
            check_crit(jh, ph, registry=self.header_registry)
            return jh
        except InvalidJWSEHeader as e:
            raise InvalidJWEData(str(e)) from e

    def _get_alg_enc_from_headers(self, jh):
        algname = jh.get('alg', None)
        if algname is None:
            raise InvalidJWEData('Missing "alg" from headers')
        alg = self._jwa_keymgmt(algname)
        encname = jh.get('enc', None)
        if encname is None:
            raise InvalidJWEData('Missing "enc" from headers')
        enc = self._jwa_enc(encname)
        return alg, enc

    def _encrypt(self, alg, enc, jh):
        aad = base64url_encode(self.objects.get('protected', ''))
        if 'aad' in self.objects:
            aad += '.' + base64url_encode(self.objects['aad'])
        aad = aad.encode('utf-8')

        compress = jh.get('zip', None)
        if compress == 'DEF':
            data = zlib.compress(self.plaintext)[2:-4]
        elif compress is None:
            data = self.plaintext
        else:
            raise ValueError('Unknown compression')

        iv, ciphertext, tag = enc.encrypt(self.cek, aad, data)
        self.objects['iv'] = iv
        self.objects['ciphertext'] = ciphertext
        self.objects['tag'] = tag

    def add_recipient(self, key, header=None):
        """Encrypt the plaintext with the given key.

        :param key: A JWK key or password of appropriate type for the 'alg'
         provided in the JOSE Headers.
        :param header: A JSON string representing the per-recipient header.

        :raises ValueError: if the plaintext is missing or not of type bytes.
        :raises ValueError: if the compression type is unknown.
        :raises InvalidJWAAlgorithm: if the 'alg' provided in the JOSE
         headers is missing or unknown, or otherwise not implemented.
        """
        if self.plaintext is None:
            raise ValueError('Missing plaintext')
        if not isinstance(self.plaintext, bytes):
            raise ValueError("Plaintext must be 'bytes'")

        if isinstance(header, dict):
            header = json_encode(header)

        jh = self._get_jose_header(header)
        alg, enc = self._get_alg_enc_from_headers(jh)

        rec = {}
        if header:
            rec['header'] = header

        wrapped = alg.wrap(key, enc.wrap_key_size, self.cek, jh)
        self.cek = wrapped['cek']

        if 'ek' in wrapped:
            rec['encrypted_key'] = wrapped['ek']

        if 'header' in wrapped:
            h = json_decode(rec.get('header', '{}'))
            nh = self._merge_headers(h, wrapped['header'])
            rec['header'] = json_encode(nh)

        if 'ciphertext' not in self.objects:
            self._encrypt(alg, enc, jh)

        if 'recipients' in self.objects:
            self.objects['recipients'].append(rec)
        elif self.flattened:
            if 'encrypted_key' in self.objects or 'header' in self.objects:
                self.objects['recipients'] = []
                n = {}
                if 'encrypted_key' in self.objects:
                    n['encrypted_key'] = self.objects.pop('encrypted_key')
                if 'header' in self.objects:
                    n['header'] = self.objects.pop('header')
                self.objects['recipients'].append(n)
                self.objects['recipients'].append(rec)
            else:
                self.objects.update(rec)
        else:
            self.objects['recipients'] = [rec]

    def rekey(self, key, new_key, header=None):
        """Re-wrap a recipient's CEK under a new key.

        The token is first authenticated with ``key``.  Only after the
        protected header, AAD, IV, ciphertext and tag have been verified is
        the existing CEK wrapped for ``new_key``.  The content encryption is
        never repeated, so those authenticated bytes are kept exactly as
        they were.  Existing recipients are replaced by the new one; the
        original object is never modified.

        :param key: The current recipient key (:class:`jwcrypto.jwk.JWK`)
         or password able to decrypt the token.
        :param new_key: The new recipient key, appropriate for the token's
         key management algorithm.
        :param header: An optional JSON string or dict with additional
         *per-recipient* header parameters.  Parameters already present in
         the protected or shared unprotected header cannot be changed.

        :raises InvalidJWEOperation: if the token has no ciphertext, the
         key management algorithm cannot reuse a CEK, the protected header
         would have to change, or recipients use incompatible algorithms.
        :raises InvalidJWEData: if the old token cannot be authenticated or
         a recipient header is invalid.

        :return: A new :class:`JWE` object encrypted for ``new_key``
        :rtype: JWE
        """
        if 'ciphertext' not in self.objects:
            raise InvalidJWEOperation('No available ciphertext')

        if header is not None:
            if isinstance(header, dict):
                header = json_encode(header)
            try:
                caller_header = json_decode(header)
            except ValueError as e:
                raise InvalidJWEOperation(
                    'Invalid recipient header', e) from e
            if not isinstance(caller_header, dict):
                raise InvalidJWEOperation(
                    'Recipient header must be a JSON object')
        else:
            caller_header = {}

        if 'recipients' in self.objects:
            recipients = self.objects['recipients']
            if len(recipients) > default_max_recipients:
                raise InvalidJWEData(
                    'Too many recipients (%d)' % len(recipients))
            if not recipients:
                raise InvalidJWEData('No recipients')
            ppe_list = recipients
            has_recipients = True
        else:
            ppe_list = [self.objects]
            has_recipients = False

        # Work out the algorithms from the headers only.  In particular,
        # reject modes that derive the CEK from the recipient key before
        # asking for or generating anything.
        alg_names = []
        enc_names = set()
        for ppe in ppe_list:
            try:
                jh = self._get_jose_header(ppe.get('header'))
            except ValueError as e:
                raise InvalidJWEData('Invalid header encoding', e) from e
            alg_name = jh.get('alg')
            if alg_name is None:
                raise InvalidJWEData('Missing "alg" from headers')
            enc_name = jh.get('enc')
            if enc_name is None:
                raise InvalidJWEData('Missing "enc" from headers')
            self._jwa_keymgmt(alg_name)
            self._jwa_enc(enc_name)
            if alg_name not in rekey_keymgmt_algs:
                raise InvalidJWEOperation(_rekey_alg_error(alg_name))
            alg_names.append(alg_name)
            enc_names.add(enc_name)

        if len(enc_names) != 1:
            raise InvalidJWEOperation(
                'Recipients use different content encryption algorithms')
        enc_name = enc_names.pop()
        if len(set(alg_names)) != 1:
            raise InvalidJWEOperation(
                'Recipients use different key management algorithms')
        alg_name = alg_names[0]

        protected = json_decode(self.objects.get('protected', '{}'))
        unprotected = json_decode(self.objects.get('unprotected', '{}'))

        # The key management algorithm may only change when it is not in
        # the protected or shared header; changing either would alter
        # authenticated bytes or shared semantics.
        requested_alg = caller_header.get('alg', alg_name)
        if requested_alg not in rekey_keymgmt_algs:
            raise InvalidJWEOperation(_rekey_alg_error(str(requested_alg)))
        if requested_alg != alg_name:
            if 'alg' in protected:
                raise InvalidJWEOperation(
                    'Cannot change protected header parameter "alg"')
            if 'alg' in unprotected:
                raise InvalidJWEOperation(
                    'Cannot change shared header parameter "alg"')
            alg_name = requested_alg
        if caller_header.get('enc', enc_name) != enc_name:
            raise InvalidJWEOperation(
                'Cannot change protected header parameter "enc"')

        # Authenticate the old token and recover its CEK without expanding
        # the payload.  This only reports success after the content tag has
        # been verified, and never writes any state to this object.
        cek = self._authenticated_cek(key, ppe_list)

        old_recipient_header = {}
        if len(ppe_list) == 1:
            old_recipient_header = json_decode(
                ppe_list[0].get('header', '{}'))

        # Keep harmless custom per-recipient headers, but drop key-specific
        # values that belong to the old wrapping (or the old key).
        generated = {'alg', 'enc', 'kid', 'epk', 'iv', 'tag', 'p2s', 'p2c'}
        rec_header = {}
        for name, value in old_recipient_header.items():
            if name not in generated:
                rec_header[name] = value

        # alg/enc must be available to the new wrapping headers somewhere.
        for name, value in (('alg', alg_name), ('enc', enc_name)):
            if name not in protected and name not in unprotected:
                rec_header[name] = value

        # A caller supplied header is per-recipient only.  Refuse requests
        # that would modify authenticated or shared headers.
        for name, value in caller_header.items():
            if name == 'aad':
                raise InvalidJWEOperation(
                    'AAD is a top-level authenticated member, not a header')
            if name in ('alg', 'enc'):
                continue
            if name in ('epk', 'iv', 'tag', 'p2s', 'p2c'):
                raise InvalidJWEOperation(
                    'Header parameter "%s" is generated by the key '
                    'management algorithm' % name)
            if name in protected:
                if protected[name] != value:
                    raise InvalidJWEOperation(
                        'Cannot change protected header parameter "%s"' %
                        name)
                continue
            if name in unprotected:
                if unprotected[name] != value:
                    raise InvalidJWEOperation(
                        'Cannot override shared unprotected header '
                        'parameter "%s"' % name)
                continue
            rec_header[name] = value

        # Prefer the new key's identity when it exposes one, unless kid is
        # already fixed by the protected/shared header or the caller.
        try:
            new_kid = new_key.get('kid')
        except AttributeError:
            new_kid = None
        if new_kid:
            fixed_kid = caller_header.get(
                'kid', protected.get('kid', unprotected.get('kid')))
            if fixed_kid and fixed_kid != new_kid:
                raise InvalidJWEOperation(
                    'New key "kid" does not match the token header')
            if not fixed_kid and 'kid' not in protected and \
                    'kid' not in unprotected:
                rec_header['kid'] = new_kid

        # Build the result as an independent object.  The CEK and plaintext
        # are never attached to it and stay unavailable until a new decrypt.
        result = JWE(flattened=self.flattened,
                     algs=self._allowed_algs,
                     header_registry=None)
        result.header_registry = copy.deepcopy(self.header_registry)
        result.objects = copy.deepcopy(self.objects)
        result.plaintext = None
        result.cek = None
        result.decryptlog = None
        for name in ('recipients', 'encrypted_key', 'header'):
            result.objects.pop(name, None)

        # pylint: disable=protected-access
        jh = result._get_jose_header(
            json_encode(rec_header) if rec_header else None)
        alg, enc = result._get_alg_enc_from_headers(jh)
        # pylint: enable=protected-access

        wrapped = None
        try:
            wrapped = alg.wrap(new_key, enc.wrap_key_size, cek, jh)
            if wrapped.get('cek') != cek:
                raise InvalidJWEOperation(
                    'Key management algorithm did not reuse the CEK')

            ek = wrapped.get('ek', b'')
            wrapped_header = wrapped.get('header', {})
            if not isinstance(wrapped_header, dict):
                wrapped_header = json_decode(wrapped_header)
            collision = set(wrapped_header) & (
                set(protected) | set(unprotected))
            if collision:
                raise InvalidJWEOperation(
                    'Re-keying would change protected or shared header '
                    'parameter(s): %s' % ', '.join(sorted(collision)))
            try:
                rec_header = merge_headers(rec_header, wrapped_header,
                                           registry=self.header_registry)
            except InvalidJWSEHeader as e:
                raise InvalidJWEData(str(e)) from e

            # The wrapping headers must also agree with any alg/enc that
            # are already in the protected or shared unprotected header.
            for name, value in wrapped_header.items():
                if name in protected and protected[name] != value:
                    raise InvalidJWEOperation(
                        'Re-keying would change protected header '
                        'parameter "%s"' % name)
                if name in unprotected and unprotected[name] != value:
                    raise InvalidJWEOperation(
                        'Re-keying would change shared header '
                        'parameter "%s"' % name)

            rec = {}
            if ek:
                rec['encrypted_key'] = ek
            if rec_header:
                rec['header'] = json_encode(rec_header)

            if has_recipients:
                result.objects['recipients'] = [rec]
            else:
                result.objects.update(rec)
            result.cek = None
            result.plaintext = None
            return result
        finally:
            wrapped = None
            cek = None

    def rewrap(self, key, new_key, header=None):
        """Alias for :meth:`rekey`."""
        return self.rekey(key, new_key, header=header)

    def rekey_recipient(self, key, new_key, header=None):
        """Alias for :meth:`rekey`."""
        return self.rekey(key, new_key, header=header)

    def rewrap_recipient(self, key, new_key, header=None):
        """Alias for :meth:`rekey`."""
        return self.rekey(key, new_key, header=header)

    def serialize(self, compact=False):
        """Serializes the object into a JWE token.

        :param compact(boolean): if True generates the compact
         representation, otherwise generates a standard JSON format.

        :raises InvalidJWEOperation: if the object cannot be serialized
         with the compact representation and `compact` is True.
        :raises InvalidJWEOperation: if no recipients have been added
         to the object.

        :return: A json formatted string or a compact representation string
        :rtype: `str`
        """

        if 'ciphertext' not in self.objects:
            raise InvalidJWEOperation("No available ciphertext")

        if compact:
            for invalid in 'aad', 'unprotected':
                if invalid in self.objects:
                    raise InvalidJWEOperation(
                        "Can't use compact encoding when the '%s' parameter "
                        "is set" % invalid)
            if 'protected' not in self.objects:
                raise InvalidJWEOperation(
                    "Can't use compact encoding without protected headers")
            else:
                ph = json_decode(self.objects['protected'])
                for required in 'alg', 'enc':
                    if required not in ph:
                        raise InvalidJWEOperation(
                            "Can't use compact encoding, '%s' must be in the "
                            "protected header" % required)
            if 'recipients' in self.objects:
                if len(self.objects['recipients']) != 1:
                    raise InvalidJWEOperation("Invalid number of recipients")
                rec = self.objects['recipients'][0]
            else:
                rec = self.objects
            if 'header' in rec:
                # The AESGCMKW algorithm generates data (iv, tag) we put in the
                # per-recipient unprotected header by default. Move it to the
                # protected header and re-encrypt the payload, as the protected
                # header is used as additional authenticated data.
                h = json_decode(rec['header'])
                ph = json_decode(self.objects['protected'])
                nph = self._merge_headers(h, ph)
                self.objects['protected'] = json_encode(nph)
                jh = self._get_jose_header()
                alg, enc = self._get_alg_enc_from_headers(jh)
                self._encrypt(alg, enc, jh)
                del rec['header']

            return '.'.join([base64url_encode(self.objects['protected']),
                             base64url_encode(rec.get('encrypted_key', '')),
                             base64url_encode(self.objects['iv']),
                             base64url_encode(self.objects['ciphertext']),
                             base64url_encode(self.objects['tag'])])
        else:
            obj = self.objects
            enc = {'ciphertext': base64url_encode(obj['ciphertext']),
                   'iv': base64url_encode(obj['iv']),
                   'tag': base64url_encode(self.objects['tag'])}
            if 'protected' in obj:
                enc['protected'] = base64url_encode(obj['protected'])
            if 'unprotected' in obj:
                enc['unprotected'] = json_decode(obj['unprotected'])
            if 'aad' in obj:
                enc['aad'] = base64url_encode(obj['aad'])
            if 'recipients' in obj:
                enc['recipients'] = []
                for rec in obj['recipients']:
                    e = {}
                    if 'encrypted_key' in rec:
                        e['encrypted_key'] = \
                            base64url_encode(rec['encrypted_key'])
                    if 'header' in rec:
                        e['header'] = json_decode(rec['header'])
                    enc['recipients'].append(e)
            else:
                if 'encrypted_key' in obj:
                    enc['encrypted_key'] = \
                        base64url_encode(obj['encrypted_key'])
                if 'header' in obj:
                    enc['header'] = json_decode(obj['header'])
            return json_encode(enc)

    def _unwrap_decrypt(self, alg, enc, key, enckey, header,
                        aad, iv, ciphertext, tag):
        cek = alg.unwrap(key, enc.wrap_key_size, enckey, header)
        data = enc.decrypt(cek, aad, iv, ciphertext, tag)
        self.decryptlog.append('Success')
        self.cek = cek
        return data

    def _authenticated_cek(self, key, ppe_list):
        """Return the CEK only after the content tag is verified.

        Unlike :meth:`decrypt` this neither stores the CEK on the object nor
        decompresses the payload.  A CEK is returned only for a recipient
        whose tag verification succeeded.
        """
        aad = base64url_encode(self.objects.get('protected', ''))
        if 'aad' in self.objects:
            aad += '.' + base64url_encode(self.objects['aad'])
        aad = aad.encode('utf-8')

        for ppe in ppe_list:
            jh = self._get_jose_header(ppe.get('header'))
            try:
                validate_headers(jh, registry=self.header_registry,
                                 target=self)
            except InvalidJWSEHeader as e:
                raise InvalidJWEData(str(e)) from e

            alg = self._jwa_keymgmt(jh.get('alg', None))
            enc = self._jwa_enc(jh.get('enc', None))
            enckey = ppe.get('encrypted_key', b'')

            if isinstance(key, JWKSet):
                keys = key
                if 'kid' in jh:
                    kid_keys = key.get_keys(jh['kid'])
                    if not kid_keys:
                        continue
                    keys = kid_keys
            else:
                keys = [key]

            for k in keys:
                try:
                    cek = alg.unwrap(k, enc.wrap_key_size, enckey, jh)
                    # Raises unless the authenticated tag is valid.  The
                    # plaintext is intentionally discarded.
                    enc.decrypt(cek, aad, self.objects['iv'],
                                self.objects['ciphertext'],
                                self.objects['tag'])
                    return cek
                except Exception:  # pylint: disable=broad-except
                    pass

        if isinstance(key, JWKSet):
            raise JWKeyNotFound('Key Not found in JWKSet')
        raise InvalidJWEData('No recipient matched the provided key')

    # FIXME: allow to specify which algorithms to accept as valid
    def _decrypt(self, key, ppe, max_plaintext=default_max_plaintext_size):

        jh = self._get_jose_header(ppe.get('header', None))

        # TODO: allow caller to specify list of headers it understands
        try:
            validate_headers(jh, registry=self.header_registry, target=self)
        except InvalidJWSEHeader as e:
            raise InvalidJWEData(str(e)) from e

        alg = self._jwa_keymgmt(jh.get('alg', None))
        enc = self._jwa_enc(jh.get('enc', None))

        aad = base64url_encode(self.objects.get('protected', ''))
        if 'aad' in self.objects:
            aad += '.' + base64url_encode(self.objects['aad'])
        aad = aad.encode('utf-8')

        if isinstance(key, JWKSet):
            keys = key
            if 'kid' in jh:
                kid_keys = key.get_keys(jh['kid'])
                if not kid_keys:
                    raise JWKeyNotFound('Key ID {} not in key set'.format(
                                        jh['kid']))
                keys = kid_keys

            for k in keys:
                try:
                    data = self._unwrap_decrypt(alg, enc, k,
                                                ppe.get('encrypted_key', b''),
                                                jh, aad, self.objects['iv'],
                                                self.objects['ciphertext'],
                                                self.objects['tag'])
                    self.decryptlog.append("Success")
                    break
                except Exception as e:  # pylint: disable=broad-except
                    keyid = k.get('kid', k.thumbprint())
                    self.decryptlog.append('Key [{}] failed: [{}]'.format(
                                           keyid, repr(e)))

            if "Success" not in self.decryptlog:
                raise JWKeyNotFound('No working key found in key set')
        else:
            data = self._unwrap_decrypt(alg, enc, key,
                                        ppe.get('encrypted_key', b''),
                                        jh, aad, self.objects['iv'],
                                        self.objects['ciphertext'],
                                        self.objects['tag'])

        compress = jh.get('zip', None)
        if compress == 'DEF':
            if len(data) > default_max_compressed_size:
                raise InvalidJWEData(
                    'Compressed data exceeds maximum allowed'
                    'size' + f' ({default_max_compressed_size})')
            do = zlib.decompressobj(wbits=-zlib.MAX_WBITS)
            self.plaintext = do.decompress(data, max_plaintext)
            if do.unconsumed_tail or not do.eof:
                self.plaintext = None
                raise InvalidJWEData(
                    'Compressed data exceeds maximum allowed'
                    'output size' + f' ({max_plaintext})')
        elif compress is None:
            self.plaintext = data
        else:
            raise ValueError('Unknown compression')

    def decrypt(self, key, max_plaintext=0):
        """Decrypt a JWE token.

        :param key: The (:class:`jwcrypto.jwk.JWK`) decryption key.
        :param key: A (:class:`jwcrypto.jwk.JWK`) decryption key,
         or a (:class:`jwcrypto.jwk.JWKSet`) that contains a key indexed
         by the 'kid' header or (deprecated) a string containing a password.
        :param max_plaintext: Maximum plaintext size allowed, 0 means
         the library default applies. Application writers are recommended
         to set a limit here if they know what is the max plaintext size
         for their application.

        :raises InvalidJWEOperation: if the key is not a JWK object.
        :raises InvalidJWEData: if the ciphertext can't be decrypted or
         the object is otherwise malformed.
        :raises JWKeyNotFound: if key is a JWKSet and the key is not found.
        """

        self.plaintext = None
        if max_plaintext == 0:
            max_plaintext = default_max_plaintext_size

        if 'ciphertext' not in self.objects:
            raise InvalidJWEOperation("No available ciphertext")
        self.decryptlog = []
        missingkey = False

        if 'recipients' in self.objects:
            if len(self.objects['recipients']) > default_max_recipients:
                raise InvalidJWEData(
                    'Too many recipients (%d)' %
                    len(self.objects['recipients']))
            for rec in self.objects['recipients']:
                try:
                    self._decrypt(key, rec, max_plaintext=max_plaintext)
                    # Stop after the first successful recipient.
                    if self.plaintext is not None:
                        break
                except Exception as e:  # pylint: disable=broad-except
                    if isinstance(e, JWKeyNotFound):
                        missingkey = True
                    self.decryptlog.append('Failed: [%s]' % repr(e))
        else:
            try:
                self._decrypt(key, self.objects, max_plaintext=max_plaintext)
            except Exception as e:  # pylint: disable=broad-except
                if isinstance(e, JWKeyNotFound):
                    missingkey = True
                self.decryptlog.append('Failed: [%s]' % repr(e))

        if not self.plaintext:
            if missingkey:
                raise JWKeyNotFound("Key Not found in JWKSet")
            raise InvalidJWEData('No recipient matched the provided '
                                 'key' + repr(self.decryptlog))

    def deserialize(self, raw_jwe, key=None):
        """Deserialize a JWE token.

        NOTE: Destroys any current status and tries to import the raw
        JWE provided.

        If a key is provided a decryption step will be attempted after
        the object is successfully deserialized.

        :param raw_jwe: a 'raw' JWE token (JSON Encoded or Compact
         notation) string.
        :param key: A (:class:`jwcrypto.jwk.JWK`) decryption key,
         or a (:class:`jwcrypto.jwk.JWKSet`) that contains a key indexed
         by the 'kid' header or (deprecated) a string containing a password
         (optional).

        :raises InvalidJWEData: if the raw object is an invalid JWE token.
        :raises InvalidJWEOperation: if the decryption fails.
        """

        self.objects = {}
        self.plaintext = None
        self.cek = None

        o = {}
        try:
            try:
                djwe = json_decode(raw_jwe)
                o['iv'] = base64url_decode(djwe['iv'])
                o['ciphertext'] = base64url_decode(djwe['ciphertext'])
                o['tag'] = base64url_decode(djwe['tag'])
                if 'protected' in djwe:
                    p = base64url_decode(djwe['protected'])
                    o['protected'] = p.decode('utf-8')
                if 'unprotected' in djwe:
                    o['unprotected'] = json_encode(djwe['unprotected'])
                if 'aad' in djwe:
                    o['aad'] = base64url_decode(djwe['aad'])
                if 'recipients' in djwe:
                    o['recipients'] = []
                    for rec in djwe['recipients']:
                        e = {}
                        if 'encrypted_key' in rec:
                            e['encrypted_key'] = \
                                base64url_decode(rec['encrypted_key'])
                        if 'header' in rec:
                            e['header'] = json_encode(rec['header'])
                        o['recipients'].append(e)
                else:
                    if 'encrypted_key' in djwe:
                        o['encrypted_key'] = \
                            base64url_decode(djwe['encrypted_key'])
                    if 'header' in djwe:
                        o['header'] = json_encode(djwe['header'])

            except ValueError as e:
                # process up to 5 dots, if we have 5+ dots we get more than 5
                # chunks and that means we have a malformed JWE
                data = raw_jwe.split('.', 5)
                if len(data) != 5:
                    raise InvalidJWEData() from e
                p = base64url_decode(data[0])
                o['protected'] = p.decode('utf-8')
                ekey = base64url_decode(data[1])
                if ekey != b'':
                    o['encrypted_key'] = base64url_decode(data[1])
                o['iv'] = base64url_decode(data[2])
                o['ciphertext'] = base64url_decode(data[3])
                o['tag'] = base64url_decode(data[4])

            self.objects = o

        except Exception as e:  # pylint: disable=broad-except
            raise InvalidJWEData('Invalid format', repr(e)) from e

        if key:
            self.decrypt(key)

    @property
    def payload(self):
        if not self.plaintext:
            raise InvalidJWEOperation("Plaintext not available")
        return self.plaintext

    @property
    def jose_header(self):
        if 'recipients' in self.objects:
            jhl = []
            for rec in self.objects['recipients']:
                jhl.append(self._get_jose_header(rec.get('header')))
            return jhl
        jh = self._get_jose_header(self.objects.get('header'))
        if len(jh) == 0:
            raise InvalidJWEOperation("JOSE Header not available")
        return jh

    @classmethod
    def from_jose_token(cls, token):
        """Creates a JWE object from a serialized JWE token.

        :param token: A string with the json or compat representation
         of the token.

        :raises InvalidJWEData: if the raw object is an invalid JWE token.

        :return: A JWE token
        :rtype: JWE
        """

        obj = cls()
        obj.deserialize(token)
        return obj

    def __eq__(self, other):
        if not isinstance(other, JWE):
            return False
        try:
            return self.serialize() == other.serialize()
        except Exception:  # pylint: disable=broad-except
            data1 = {'plaintext': self.plaintext}
            data1.update(self.objects)
            data2 = {'plaintext': other.plaintext}
            data2.update(other.objects)
            return data1 == data2

    def __str__(self):
        try:
            return self.serialize()
        except Exception:  # pylint: disable=broad-except
            return self.__repr__()

    def __repr__(self):
        try:
            return f'JWE.from_json_token("{self.serialize()}")'
        except Exception:  # pylint: disable=broad-except
            plaintext = repr(self.plaintext)
            protected = self.objects.get('protected')
            unprotected = self.objects.get('unprotected')
            aad = self.objects.get('aad')
            algs = self._allowed_algs
            return f'JWE(plaintext={plaintext}, ' + \
                   f'protected={protected}, ' + \
                   f'unprotected={unprotected}, ' + \
                   f'aad={aad}, algs={algs})'
