# Multi-signature JSON JWS: b64 default vs explicit

Scope: embedded-payload general JWS (`{"payload":..., "signatures":[...]}`).
Detached / streaming payload interfaces are intentionally out of scope.

## Run

    .venv/bin/python repro/repro_b64_matrix.py

## What it builds

Real HS256 signatures over a shared payload, in two matrices:

- Matrix A — semantically equivalent headers, all meaning `b64=true`:
  `absent` (header omitted, RFC 7797 default), explicit `true`, across
  every ordering.
- Matrix B — a genuine conflict, `b64:false` versus `true`/`absent`,
  across every ordering.

Each carried signature is independently recomputed over the exact signing
input bytes `ASCII(protected) || '.' || payload-as-carried` and compared
with `hmac.compare_digest`. The fixture MAC is also cross-checked against
`JWSCore.sign()`. Acceptance never relies on two printed strings matching.

## Result after the fix

- Matrix A: every ordering deserializes to the same payload bytes and every
  signature verifies.
- Matrix B: every ordering is consistently rejected
  (`InvalidJWSObject: conflicting b64 values`).

## Root cause (pre-fix)

`JWS._deserialize_b64` stored an absent `b64` header as `None` instead of
normalizing it to the default `True`. In a general JWS the per-signature
loop processed entries in listed order, so:

- `true` then `absent` raised a spurious conflict (while `absent` then
  `true` was accepted);
- `absent` then `false` was wrongly accepted (while `false` then `absent`
  was rejected).

The fix normalizes an absent header to `True` before the equality check,
so equivalent defaults never depend on ordering and genuine conflicts are
rejected in every order. Regression tests live in
`jwcrypto/tests.py::TestGeneralJWSB64Ordering`.
