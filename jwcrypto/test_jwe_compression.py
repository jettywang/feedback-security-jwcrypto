# Copyright (C) 2026 JWCrypto Project Contributors - see LICENSE file

"""Regression tests for compressed (``zip=DEF``) JWE decryption.

These tests keep two verification layers deliberately separate:

1. The JWE content-encryption authentication tag (A128GCM here): every
   malformed DEFLATE stream below is wrapped in a *freshly encrypted,
   correctly tagged* envelope, so a rejection proves the compression
   stream itself is validated, not just the AEAD.
2. The integrity of the raw DEFLATE stream produced after successful
   authentication: it must be exactly one complete stream, with no
   truncation, concatenation or trailing bytes.

Each test documents the shape of the inner stream, the expected result
and the state the ``JWE`` object must be left in afterwards.
"""

import os
import unittest
import zlib

from jwcrypto import jwe, jwk
from jwcrypto.common import InvalidJWEOperation
from jwcrypto.common import base64url_decode, base64url_encode
from jwcrypto.common import json_encode
from jwcrypto.jwa import JWA

# A fixed 128-bit CEK used with the direct key management ('dir') and
# A128GCM content encryption algorithms.
CEK = b'A' * 16
JWK = jwk.JWK(kty='oct', k=base64url_encode(CEK))
_ENC = JWA.encryption_alg('A128GCM')

PROTECTED_HEADER = {'alg': 'dir', 'enc': 'A128GCM', 'zip': 'DEF'}


def raw_deflate(data):
    """Return the raw DEFLATE encoding (no zlib header, no Adler trailer)."""
    return zlib.compress(data)[2:-4]


def build_compressed_jwe(inner):
    """Encrypt arbitrary inner bytes into a valid, correctly tagged JWE.

    The protected header advertises ``zip=DEF`` and the AAD used for the
    GCM tag is the base64url-encoded protected header, exactly as the
    library computes it internally. The resulting token therefore passes
    authentication even when *inner* is not a well formed DEFLATE stream.
    """
    protected = json_encode(PROTECTED_HEADER)
    aad = base64url_encode(protected).encode('utf-8')
    iv, ciphertext, tag = _ENC.encrypt(CEK, aad, inner)
    return '.'.join([
        base64url_encode(protected),
        '',
        base64url_encode(iv),
        base64url_encode(ciphertext),
        base64url_encode(tag),
    ])


def fresh_jwe(token):
    obj = jwe.JWE()
    obj.deserialize(token)
    return obj


# A normal, well formed stream reused by several cases.
PLAINTEXT = b'compressed-jwe-regression-' * 16
VALID_STREAM = raw_deflate(PLAINTEXT)


class CompressedJWETests(unittest.TestCase):

    def assert_rejected(self, token, message, **decrypt_kwargs):
        """Decryption must fail and must not expose any plaintext."""
        obj = fresh_jwe(token)
        with self.assertRaises(jwe.InvalidJWEData) as ctx:
            obj.decrypt(JWK, **decrypt_kwargs)
        self.assertIn(message, str(ctx.exception))
        # Nothing may be retrievable from the failed object.
        self.assertIsNone(obj.plaintext)
        with self.assertRaises(InvalidJWEOperation):
            obj.payload
        return obj

    def test_valid_raw_deflate_stream_round_trips(self):
        """A legal single raw DEFLATE stream decrypts to the plaintext."""
        token = build_compressed_jwe(VALID_STREAM)
        obj = fresh_jwe(token)
        obj.decrypt(JWK)
        self.assertEqual(obj.payload, PLAINTEXT)

    def test_truncated_stream_is_rejected(self):
        """A stream cut before its end-of-stream marker is incomplete.

        Authentication still succeeds (the envelope is freshly tagged),
        but the DEFLATE stream never reaches EOF, so it must be rejected
        as an incomplete stream rather than silently decompressed.
        """
        for cut in (1, 4, len(VALID_STREAM) // 2):
            token = build_compressed_jwe(VALID_STREAM[:-cut])
            self.assert_rejected(
                token, 'Incomplete or trailing data in compressed stream')

    def test_empty_compressed_payload_is_rejected(self):
        """An empty inner payload cannot be a complete DEFLATE stream."""
        token = build_compressed_jwe(b'')
        self.assert_rejected(
            token, 'Incomplete or trailing data in compressed stream')

    def test_concatenated_streams_are_rejected(self):
        """Two complete DEFLATE streams concatenated together are invalid.

        zlib stops at the first end-of-stream marker; without an explicit
        ``unused_data`` check the second stream would be silently ignored.
        The envelope itself carries a valid authentication tag, proving
        this is a compression-integrity check.
        """
        second_stream = raw_deflate(b'second-inner-stream')
        token = build_compressed_jwe(VALID_STREAM + second_stream)
        self.assert_rejected(
            token, 'Incomplete or trailing data in compressed stream')

    def test_trailing_garbage_is_rejected(self):
        """Trailing bytes after the end-of-stream marker must be rejected."""
        for trailer in (b'\x00', b'\x00\x00\x00', b'junk-bytes'):
            token = build_compressed_jwe(VALID_STREAM + trailer)
            self.assert_rejected(
                token, 'Incomplete or trailing data in compressed stream')

    def test_corrupt_deflate_block_is_rejected(self):
        """A stream zlib cannot parse raises a library-level error.

        The raw ``zlib.error`` must be translated into ``InvalidJWEData``
        and must not propagate to callers or leave partial output behind.
        """
        token = build_compressed_jwe(b'this-is-not-a-deflate-stream')
        self.assert_rejected(token, 'Malformed compressed data')

    def test_authentication_failure_is_distinct_from_compression(self):
        """Tampered ciphertext must fail at the AEAD, before decompression.

        This documents that the compression checks above are not merely
        authentication failures in disguise: here the tag is invalid and
        the error happens in the content-encryption layer instead.
        """
        token = build_compressed_jwe(VALID_STREAM)
        parts = token.split('.')
        ciphertext = bytearray(base64url_decode(parts[3]))
        ciphertext[0] ^= 0x01
        parts[3] = base64url_encode(bytes(ciphertext))
        tampered = '.'.join(parts)

        obj = fresh_jwe(tampered)
        with self.assertRaises(jwe.InvalidJWEData) as ctx:
            obj.decrypt(JWK)
        self.assertNotIn('compressed', str(ctx.exception).lower())
        self.assertIsNone(obj.plaintext)

    def test_uncompressed_jwe_still_works(self):
        """The fix must not change ordinary uncompressed JWE behavior."""
        token = jwe.JWE(
            PLAINTEXT,
            protected={'alg': 'dir', 'enc': 'A128GCM'},
            recipient=JWK).serialize(compact=True)
        obj = fresh_jwe(token)
        obj.decrypt(JWK)
        self.assertEqual(obj.payload, PLAINTEXT)

    def test_legitimate_compressed_token_from_library_still_works(self):
        """Tokens produced by the library's own compression path work."""
        token = jwe.JWE(
            PLAINTEXT,
            protected=PROTECTED_HEADER,
            recipient=JWK).serialize(compact=True)
        obj = fresh_jwe(token)
        obj.decrypt(JWK)
        self.assertEqual(obj.payload, PLAINTEXT)


class MaxPlaintextBoundaryTests(unittest.TestCase):

    def setUp(self):
        # Highly compressible data keeps the encrypted inner stream tiny
        # while the expanded plaintext has an exact known size.
        self.exact_size = 4096
        self.payload = b'Q' * self.exact_size
        self.stream = raw_deflate(self.payload)
        self.assertLess(len(self.stream), self.exact_size)

    def test_plaintext_exactly_at_limit_is_accepted(self):
        """A plaintext whose size equals the limit is still allowed."""
        token = build_compressed_jwe(self.stream)
        obj = fresh_jwe(token)
        obj.decrypt(JWK, max_plaintext=self.exact_size)
        self.assertEqual(len(obj.payload), self.exact_size)

    def test_plaintext_one_byte_over_limit_is_rejected(self):
        """A plaintext one byte larger than the limit is rejected."""
        token = build_compressed_jwe(self.stream)
        obj = fresh_jwe(token)
        with self.assertRaises(jwe.InvalidJWEData) as ctx:
            obj.decrypt(JWK, max_plaintext=self.exact_size - 1)
        self.assertIn('output size', str(ctx.exception))
        self.assertIsNone(obj.plaintext)

    def test_limits_are_isolated_between_calls(self):
        """A restrictive call must not change the outcome of later calls."""
        token = build_compressed_jwe(self.stream)

        restricted = fresh_jwe(token)
        with self.assertRaises(jwe.InvalidJWEData):
            restricted.decrypt(JWK, max_plaintext=self.exact_size - 1)
        self.assertIsNone(restricted.plaintext)

        # The same token decrypts fine on a fresh object with a larger
        # limit; the previous rejection has no shared decompressor state.
        allowed = fresh_jwe(token)
        allowed.decrypt(JWK, max_plaintext=self.exact_size)
        self.assertEqual(len(allowed.payload), self.exact_size)

        # And a fresh restrictive call on the same object still fails.
        with self.assertRaises(jwe.InvalidJWEData):
            allowed.decrypt(JWK, max_plaintext=self.exact_size - 1)
        self.assertIsNone(allowed.plaintext)

    def test_failed_decryption_leaves_no_partial_plaintext(self):
        """Partial output buffered before a limit error must not leak."""
        token = build_compressed_jwe(self.stream)
        obj = fresh_jwe(token)
        with self.assertRaises(jwe.InvalidJWEData):
            obj.decrypt(JWK, max_plaintext=16)
        self.assertIsNone(obj.plaintext)
        with self.assertRaises(InvalidJWEOperation):
            obj.payload

    def test_decompression_never_expands_beyond_the_limit(self):
        """A compression bomb is bounded by the per-call limit.

        A small encrypted inner stream expands to far more than the
        configured limit. We instrument the decompressor output so the
        test observes directly that no chunk larger than the limit is
        ever produced, i.e. the huge plaintext is never fully expanded.
        """
        huge_plaintext = os.urandom(1) * (2 * 1024 * 1024)
        bomb_stream = raw_deflate(huge_plaintext)
        self.assertLess(len(bomb_stream), 4096)
        limit = 8192
        token = build_compressed_jwe(bomb_stream)
        obj = fresh_jwe(token)

        original_cls = zlib.decompressobj
        max_output_seen = []

        class RecordingDecompressObj:
            def __init__(self, *args, **kwargs):
                self._inner = original_cls(*args, **kwargs)

            def decompress(self, data, max_length=0):
                chunk = self._inner.decompress(data, max_length)
                max_output_seen.append(len(chunk))
                return chunk

            def __getattr__(self, name):
                return getattr(self._inner, name)

        zlib.decompressobj = RecordingDecompressObj
        try:
            with self.assertRaises(jwe.InvalidJWEData):
                obj.decrypt(JWK, max_plaintext=limit)
        finally:
            zlib.decompressobj = original_cls

        self.assertTrue(max_output_seen)
        self.assertLessEqual(max(max_output_seen), limit)
        self.assertIsNone(obj.plaintext)


if __name__ == '__main__':
    unittest.main()
