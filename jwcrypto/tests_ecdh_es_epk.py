# Copyright (C) 2026 JWCrypto Project Contributors - see LICENSE file

"""Security tests for ECDH-ES JWE ephemeral public key handling.

These tests drive the full receiver path: JWE protected header parsing,
JWK import of the ephemeral key (``epk``), the elliptic-curve key
agreement and the final authenticated decryption. Every negative case
asserts *where* it is rejected (JWK import, key agreement, or content
authentication) instead of treating every raised exception as equivalent.

All vectors are generated locally with the curves the installed
``cryptography`` backend supports; no network access is required.
"""

import binascii
import unittest

from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap

from jwcrypto import jwa
from jwcrypto import jwe
from jwcrypto import jwk
from jwcrypto.common import InvalidJWEKeyType
from jwcrypto.common import base64url_decode, base64url_encode
from jwcrypto.common import json_decode, json_encode
from jwcrypto.jwk import InvalidJWKType
from jwcrypto.jwk import InvalidJWKValue

# Rejection stages are expressed by the helper names below
# (_import_stage / _agreement_stage / the AEAD authentication check) so each
# negative test pins down where the rejection happens rather than accepting
# any exception.

PLAINTEXT = b'ecdh-es ephemeral-key test plaintext'

EC_CURVES = ['P-256', 'P-384', 'P-521']
OKP_CURVES = [c for c in ('X25519', 'X448')
              if c in jwk.ImplementedOkpCurves]


def _protected(alg, enc, **extra):
    header = {'alg': alg, 'enc': enc}
    header.update(extra)
    return json_encode(header)


def _make_token(recipient, alg='ECDH-ES', enc='A128GCM', **header_extra):
    """Encrypt locally and return the compact serialization plus the key."""
    token = jwe.JWE(PLAINTEXT,
                    _protected(alg, enc, **header_extra))
    token.add_recipient(recipient)
    return token.serialize(compact=True)


def _token_header(token):
    return json_decode(base64url_decode(token.split('.')[0]))


def _reserialize(token, header):
    parts = token.split('.')
    parts[0] = base64url_encode(json_encode(header))
    return '.'.join(parts)


class EcdhEsEpkSecurityTests(unittest.TestCase):
    """Validate ``epk`` and ``apu``/``apv`` handling on the receiving side."""

    def setUp(self):
        self.ec_key = jwk.JWK.generate(kty='EC', crv='P-256')
        self.token = _make_token(self.ec_key)
        self.header = _token_header(self.token)

    # ------------------------------------------------------------------
    # Helpers that classify the rejection stage precisely.
    # ------------------------------------------------------------------
    def _import_stage(self, epk):
        """Run only the JWK import of the ephemeral key."""
        return jwk.JWK(**epk)

    def _agreement_stage(self, recipient, header, alg='ECDH-ES',
                         bitsize=128, encrypted_key=b''):
        """Run header parse + JWK import + ECDH agreement/unwrap only."""
        algorithm = jwa.JWA.keymgmt_alg(alg)
        return algorithm.unwrap(recipient, bitsize, encrypted_key, header)

    def _full_decrypt(self, token, recipient):
        """Run the complete receiver path and return the JWE object."""
        obj = jwe.JWE()
        obj.deserialize(token, recipient)
        return obj

    def _assert_import_rejects(self, epk, expected):
        with self.assertRaises(expected) as ctx:
            self._import_stage(epk)
        return ctx.exception

    def _assert_agreement_rejects(self, recipient, header, expected,
                                  alg='ECDH-ES', bitsize=128,
                                  encrypted_key=b''):
        # A well-formed epk must always import first, proving the failure
        # happens during the key agreement rather than at JWK import.
        self._import_stage(header['epk'])
        with self.assertRaises(expected) as ctx:
            self._agreement_stage(recipient, header, alg, bitsize,
                                  encrypted_key)
        return ctx.exception

    def _assert_auth_rejects(self, token, recipient):
        # Import and agreement both succeed; only the AEAD tag must fail,
        # and no plaintext may survive the failed decryption.
        obj = jwe.JWE()
        with self.assertRaises(jwe.InvalidJWEData) as ctx:
            obj.deserialize(token, recipient)
        self.assertIn('InvalidTag', repr(obj.decryptlog))
        self.assertIsNone(obj.plaintext)
        self.assertIsNone(obj.cek)
        return ctx.exception

    # ------------------------------------------------------------------
    # Positive control: the happy path really decrypts.
    # ------------------------------------------------------------------
    def test_valid_ec_token_decrypts(self):
        obj = self._full_decrypt(self.token, self.ec_key)
        self.assertEqual(obj.payload, PLAINTEXT)

    def test_valid_roundtrip_all_ec_curves(self):
        for curve in EC_CURVES:
            with self.subTest(curve=curve):
                recipient = jwk.JWK.generate(kty='EC', crv=curve)
                token = _make_token(recipient)
                obj = jwe.JWE()
                obj.deserialize(token, recipient)
                self.assertEqual(obj.payload, PLAINTEXT)

    @unittest.skipUnless(OKP_CURVES, 'no X25519/X448 backend support')
    def test_valid_roundtrip_all_okp_curves(self):
        for curve in OKP_CURVES:
            with self.subTest(curve=curve):
                recipient = jwk.JWK.generate(kty='OKP', crv=curve)
                token = _make_token(recipient)
                obj = jwe.JWE()
                obj.deserialize(token, recipient)
                self.assertEqual(obj.payload, PLAINTEXT)

    def test_valid_keywrap_variant_decrypts(self):
        for alg in ('ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW'):
            with self.subTest(alg=alg):
                recipient = jwk.JWK.generate(kty='EC', crv='P-256')
                token = _make_token(recipient, alg=alg)
                obj = jwe.JWE()
                obj.deserialize(token, recipient)
                self.assertEqual(obj.payload, PLAINTEXT)

    # ------------------------------------------------------------------
    # Curve mismatch: import succeeds, agreement must reject.
    # ------------------------------------------------------------------
    def test_curve_mismatch_rejected_at_agreement(self):
        for curve in ('P-384', 'P-521'):
            with self.subTest(curve=curve):
                header = dict(self.header)
                other = jwk.JWK.generate(kty='EC', crv=curve)
                header['epk'] = json_decode(other.export_public())
                # Import of the foreign epk itself is legal.
                self._import_stage(header['epk'])
                self._assert_agreement_rejects(
                    self.ec_key, header, ValueError)

    @unittest.skipUnless(OKP_CURVES, 'no X25519/X448 backend support')
    def test_okp_curve_mismatch_rejected_at_agreement(self):
        if len(OKP_CURVES) < 2:
            self.skipTest('need two OKP curves for mismatch')
        first, second = OKP_CURVES
        recipient = jwk.JWK.generate(kty='OKP', crv=first)
        token = _make_token(recipient)
        header = _token_header(token)
        other = jwk.JWK.generate(kty='OKP', crv=second)
        header['epk'] = json_decode(other.export_public())
        self._import_stage(header['epk'])
        self._assert_agreement_rejects(recipient, header, TypeError)

    def test_ec_vs_okp_family_mismatch_rejected_at_agreement(self):
        if not OKP_CURVES:
            self.skipTest('no X25519/X448 backend support')
        curve = OKP_CURVES[0]
        okp_recipient = jwk.JWK.generate(kty='OKP', crv=curve)
        token = _make_token(okp_recipient)
        header = _token_header(token)
        ec_epk = jwk.JWK.generate(kty='EC', crv='P-256')
        header['epk'] = json_decode(ec_epk.export_public())
        self._import_stage(header['epk'])
        self._assert_agreement_rejects(okp_recipient, header, TypeError)

    # ------------------------------------------------------------------
    # Invalid coordinates: import accepts the encoding, agreement rejects
    # because the point is not on the recipient's curve.
    # ------------------------------------------------------------------
    def test_point_not_on_curve_rejected_at_agreement(self):
        zero = base64url_encode(b'\x00' * 32)
        for mutate in (
            lambda epk: epk.update(x=zero, y=zero),
            lambda epk: epk.update(
                x=base64url_encode(b'\xff' * 33),
                y=base64url_encode(b'\x00' * 32)),
            lambda epk: epk.update(x=epk['y'], y=epk['x']),
        ):
            with self.subTest():
                header = dict(self.header)
                mutate(header['epk'])
                self._import_stage(header['epk'])
                self._assert_agreement_rejects(
                    self.ec_key, header, ValueError)

    def test_unknown_curve_rejected_at_agreement(self):
        header = dict(self.header)
        header['epk']['crv'] = 'P-999'
        self._import_stage(header['epk'])
        self._assert_agreement_rejects(
            self.ec_key, header, InvalidJWKValue)

    # ------------------------------------------------------------------
    # Wrong ephemeral key type: import succeeds, agreement rejects.
    # ------------------------------------------------------------------
    def test_wrong_epk_kty_rejected_at_agreement(self):
        cases = [
            ('oct', lambda: {
                'kty': 'oct',
                'k': base64url_encode(b'0' * 32)}),
            ('RSA', lambda: json_decode(
                jwk.JWK.generate(kty='RSA', size=2048).export_public())),
        ]
        if OKP_CURVES:
            okp = jwk.JWK.generate(kty='OKP', crv=OKP_CURVES[0])
            cases.append(('OKP', lambda okp=okp: json_decode(
                okp.export_public())))
        for label, factory in cases:
            with self.subTest(kty=label):
                header = dict(self.header)
                header['epk'] = factory()
                self._import_stage(header['epk'])
                self._assert_agreement_rejects(
                    self.ec_key, header, TypeError)

    def test_recipient_wrong_kty_rejected_before_agreement(self):
        # The recipient key type gate is independent of the ephemeral key
        # and must raise before any ECDH operation is attempted.
        header = dict(self.header)
        rsa_recipient = jwk.JWK.generate(kty='RSA', size=2048)
        oct_recipient = jwk.JWK.generate(kty='oct', size=128)
        for recipient in (rsa_recipient, oct_recipient):
            with self.subTest(kty=recipient['kty']):
                with self.assertRaises(InvalidJWEKeyType):
                    self._agreement_stage(recipient, header)

    @unittest.skipUnless(OKP_CURVES, 'no X25519/X448 backend support')
    def test_recipient_okp_signing_curve_rejected(self):
        # An OKP key that is not an X25519/X448 key-exchange curve must
        # be rejected by the recipient key type check.
        eddsa = jwk.JWK.generate(kty='OKP', crv='Ed25519')
        header = dict(self.header)
        with self.assertRaises(InvalidJWEKeyType):
            self._agreement_stage(eddsa, header)

    # ------------------------------------------------------------------
    # Malformed JWK material is rejected at the import stage.
    # ------------------------------------------------------------------
    def test_malformed_epk_rejected_at_import(self):
        good = self.header['epk']
        bad_b64 = dict(good, x='a!b')
        self._assert_import_rejects(bad_b64, InvalidJWKValue)

        missing_y = {k: v for k, v in good.items() if k != 'y'}
        self._assert_import_rejects(missing_y, InvalidJWKValue)

        # A non registered key type never becomes a JWK.
        with self.assertRaises(InvalidJWKType):
            jwk.JWK(kty='bogus', crv='P-256',
                    x=good['x'], y=good['y'])

    def test_relaxing_import_validation_is_detected(self):
        # If import stopped decoding/validating the coordinates, a malformed
        # 'x' would produce a JWK instead of InvalidJWKValue. This guards the
        # earliest gate so a relaxation cannot fail open into the agreement.
        good = self.header['epk']
        malformed = dict(good, x='a!b')
        with self.assertRaises(InvalidJWKValue):
            jwk.JWK(**malformed)

        # A well-formed epk still imports, proving the gate is selective.
        self._import_stage(good)

    # ------------------------------------------------------------------
    # An epk carrying private material ('d') must not change the derived
    # key: the receiver uses only the public x/y coordinates.
    # ------------------------------------------------------------------
    def test_epk_with_private_material_uses_public_coordinates(self):
        header_no_d = dict(self.header)
        header_with_d = dict(self.header)
        # A private scalar that does not match the public coordinates.
        header_with_d['epk'] = dict(
            self.header['epk'],
            d=base64url_encode(b'\x01' * 32))
        algorithm = jwa.JWA.keymgmt_alg('ECDH-ES')
        cek_no_d = algorithm.unwrap(self.ec_key, 128, b'', header_no_d)
        cek_with_d = algorithm.unwrap(self.ec_key, 128, b'',
                                      header_with_d)
        self.assertEqual(cek_no_d, cek_with_d)

        # A full, self-consistent private epk behaves identically to its
        # public counterpart when used as an ephemeral public key.
        full = jwk.JWK.generate(kty='EC', crv='P-256')
        public = json_decode(full.export_public())
        private = json_decode(full.export_private())
        self.assertIn('d', private)
        self.assertNotIn('d', public)
        header_pub = dict(self.header, epk=public)
        header_pri = dict(self.header, epk=private)
        self.assertEqual(
            algorithm.unwrap(self.ec_key, 128, b'', header_pub),
            algorithm.unwrap(self.ec_key, 128, b'', header_pri))

    # ------------------------------------------------------------------
    # Unknown ephemeral public key: agreement succeeds but the AEAD tag
    # fails, and no stale plaintext is left behind.
    # ------------------------------------------------------------------
    def _unknown_epk_token(self):
        fresh = jwk.JWK.generate(kty='EC', crv='P-256')
        header = dict(self.header)
        header['epk'] = json_decode(fresh.export_public())
        return header, _reserialize(self.token, header)

    def test_unknown_epk_fails_authentication_without_residue(self):
        header, bad_token = self._unknown_epk_token()
        # Same curve and a valid point: agreement produces a CEK.
        self._agreement_stage(self.ec_key, header)
        # The whole token must fail the authentication tag, not decrypt.
        self._assert_auth_rejects(bad_token, self.ec_key)

    def test_failed_decrypt_resets_preexisting_state(self):
        _, bad_token = self._unknown_epk_token()

        # deserialize() must wipe state of a freshly constructed object.
        obj = jwe.JWE()
        # Simulate a reused object that still holds an old plaintext.
        obj.plaintext = b'STALE-PLAINTEXT-MUST-NOT-SURVIVE'
        with self.assertRaises(jwe.InvalidJWEData):
            obj.deserialize(bad_token, self.ec_key)
        self.assertIsNone(obj.plaintext)
        self.assertIsNone(obj.cek)

    def test_failed_decrypt_call_clears_previously_decrypted_payload(self):
        # An application that reuses one JWE object across decrypt() calls
        # must never observe a previous plaintext after a failed attempt.
        _, bad_token = self._unknown_epk_token()

        # Load the malformed token without decrypting, then call decrypt()
        # directly so the state reset happens inside decrypt() rather than
        # deserialize().
        reused = jwe.JWE.from_jose_token(bad_token)
        reused.plaintext = b'STALE-PLAINTEXT-MUST-NOT-SURVIVE'
        with self.assertRaises(jwe.InvalidJWEData):
            reused.decrypt(self.ec_key)
        self.assertIsNone(reused.plaintext)
        self.assertIsNone(reused.cek)

        # A genuinely decrypted token keeps its own plaintext, proving the
        # reset only affects the failed attempt.
        good = jwe.JWE()
        good.deserialize(self.token, self.ec_key)
        self.assertEqual(good.payload, PLAINTEXT)

    # ------------------------------------------------------------------
    # apu / apv are fed into the Concat KDF OtherInfo, so legitimate
    # binding changes must alter the derived CEK rather than be ignored.
    # ------------------------------------------------------------------
    def _derived_cek(self, recipient, header, alg='ECDH-ES', bitsize=128):
        algorithm = jwa.JWA.keymgmt_alg(alg)
        return algorithm.unwrap(recipient, bitsize, b'', header)

    def test_apu_apv_empty_equivalent_to_absent(self):
        base = self._derived_cek(self.ec_key, self.header)
        for field in ('apu', 'apv'):
            with self.subTest(field=field):
                header = dict(self.header)
                header[field] = ''
                self.assertEqual(
                    base, self._derived_cek(self.ec_key, header))

    def test_apu_apv_binding_changes_derived_key(self):
        base = self._derived_cek(self.ec_key, self.header)
        alice = base64url_encode(b'Alice')
        bob = base64url_encode(b'Bob')
        cases = [
            {'apu': alice},
            {'apv': bob},
            {'apu': alice, 'apv': bob},
            # Same value in the opposite slot changes PartyU/PartyV.
            {'apu': base64url_encode(b'X')},
            {'apv': base64url_encode(b'X')},
            # Different byte lengths must not collide.
            {'apu': base64url_encode(b'A')},
            {'apu': base64url_encode(b'AA')},
        ]
        derived = []
        for extra in cases:
            with self.subTest(extra=extra):
                header = dict(self.header)
                header.update(extra)
                cek = self._derived_cek(self.ec_key, header)
                self.assertNotEqual(base, cek)
                derived.append(cek)
        # Every distinct binding must yield a distinct CEK.
        self.assertEqual(len(derived), len(set(derived)))

    def test_apu_apv_binary_encoding_roundtrip(self):
        # Include 0x00 / 0xff bytes and every value 0..255 to exercise the
        # length-prefixed OtherInfo encoding across byte boundaries.
        for value in (bytes([0, 1, 2, 255, 254]), bytes(range(256))):
            with self.subTest():
                encoded = base64url_encode(value)
                self.assertEqual(base64url_decode(encoded), value)
                recipient = jwk.JWK.generate(kty='EC', crv='P-256')
                token = _make_token(recipient, apu=encoded,
                                    apv=base64url_encode(value[::-1]))
                obj = jwe.JWE()
                obj.deserialize(token, recipient)
                self.assertEqual(obj.payload, PLAINTEXT)

    def test_malformed_apu_apv_rejected_at_agreement(self):
        for field in ('apu', 'apv'):
            for bad in ('a!b', ' '):
                with self.subTest(field=field, bad=repr(bad)):
                    header = dict(self.header)
                    header[field] = bad
                    with self.assertRaises((binascii.Error, ValueError)):
                        self._derived_cek(self.ec_key, header)

    def test_tampered_apu_apv_fails_authentication(self):
        recipient = jwk.JWK.generate(kty='EC', crv='P-256')
        token = _make_token(
            recipient,
            apu=base64url_encode(b'Alice'),
            apv=base64url_encode(b'Bob'))
        for field, replacement in (
            ('apu', base64url_encode(b'Mallory')),
            ('apv', base64url_encode(b'Eve')),
        ):
            with self.subTest(field=field):
                header = _token_header(token)
                header[field] = replacement
                self._assert_auth_rejects(
                    _reserialize(token, header), recipient)

    def test_apu_apv_binding_applies_to_keywrap_variant(self):
        recipient = jwk.JWK.generate(kty='EC', crv='P-256')
        token = _make_token(recipient, alg='ECDH-ES+A128KW',
                            apu=base64url_encode(b'Alice'))
        header = _token_header(token)
        encrypted_key = base64url_decode(token.split('.')[1])
        # Original binding unwraps the AES key-wrapped CEK successfully.
        self._agreement_stage(
            recipient, header, alg='ECDH-ES+A128KW',
            encrypted_key=encrypted_key)
        # Changing the binding makes the KEK wrong: AES key unwrap fails.
        tampered = dict(header, apu=base64url_encode(b'Mallory'))
        with self.assertRaises(InvalidUnwrap):
            self._agreement_stage(
                recipient, tampered, alg='ECDH-ES+A128KW',
                encrypted_key=encrypted_key)

    # ------------------------------------------------------------------
    # Mutation-detection tests: deliberately relaxing the curve or key
    # type validation in jwa.py must make these fail.
    # ------------------------------------------------------------------
    def test_relaxing_recipient_key_type_check_is_detected(self):
        # If _EcdhEs._check_key stopped validating the recipient kty, the
        # TypeError raised below would never be produced by this gate.
        header = dict(self.header)
        rsa_recipient = jwk.JWK.generate(kty='RSA', size=2048)
        with self.assertRaises(InvalidJWEKeyType) as ctx:
            self._agreement_stage(rsa_recipient, header)
        self.assertIn('RSA', str(ctx.exception))

        if OKP_CURVES:
            eddsa = jwk.JWK.generate(kty='OKP', crv='Ed25519')
            with self.assertRaises(InvalidJWEKeyType) as ctx:
                self._agreement_stage(eddsa, header)
            self.assertIn('Ed25519', str(ctx.exception))

    def test_relaxing_curve_check_is_detected(self):
        # A foreign-curve epk must never reach a successful agreement;
        # relaxing the curve/type handling would change the observed
        # exception away from the backend's explicit type/value error.
        foreign = jwk.JWK.generate(kty='EC', crv='P-384')
        header = dict(self.header)
        header['epk'] = json_decode(foreign.export_public())
        # Relaxing curve handling would replace this explicit backend
        # ValueError/TypeError with a successful agreement or a different
        # exception class, failing this assertion.
        with self.assertRaises((ValueError, TypeError)):
            self._agreement_stage(self.ec_key, header)
        # The genuine P-256 epk still agrees, proving only the foreign
        # curve is rejected rather than the algorithm being broken.
        self._agreement_stage(self.ec_key, self.header)

    def test_backend_curve_matches_jwk_curve(self):
        # Guard against a relaxed curve lookup that would hand the wrong
        # cryptography curve object to the agreement.
        epk = self._import_stage(self.header['epk'])
        public = epk.get_op_key('wrapKey')
        self.assertIsInstance(public.curve, SECP256R1)


if __name__ == '__main__':
    unittest.main()
