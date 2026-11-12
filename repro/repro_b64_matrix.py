"""
Minimal reproduction: multi-signature JSON JWS and b64 default vs explicit.

Scope: embedded payload only (no detached / streaming interfaces).

For every signature we independently recompute the HS256 MAC over the
EXACT signing input bytes (ASCII(protected) || '.' || payload-as-carried)
and compare it byte-for-byte against the carried signature. Acceptance is
never based on two printed strings being equal.
"""
import base64
import hashlib
import hmac
import json

from jwcrypto import jws, jwk
from jwcrypto.common import json_encode

KEY = jwk.JWK.generate(kty='oct', size=256)

PAYLOAD = b'$.02 important message'  # bytes the application intends to sign


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')


def unb64u(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# The oct JWK's op key is the base64url key-material string; jwcrypto's
# HMAC implementation MACs over the DECODED raw key bytes. Decode here so
# the independent recomputation runs over the identical key bytes.
_op = KEY.get_op_key('verify')
K = unb64u(_op) if isinstance(_op, str) else bytes(_op)


# Each variant: name -> (protected header dict, payload bytes AS CARRIED in
# the JSON 'payload' member, whether that member is base64url-encoded).
def variant_headers(kind):
    if kind == 'absent':                 # b64 header omitted -> default true
        return {'alg': 'HS256'}
    if kind == 'true':                   # explicit b64:true
        return {'alg': 'HS256', 'b64': True}
    if kind == 'false':                  # explicit b64:false, must be critical
        return {'alg': 'HS256', 'b64': False, 'crit': ['b64']}
    raise ValueError(kind)


def make_signature(kind):
    hdr = variant_headers(kind)
    protected_json = json_encode(hdr)          # canonical compact JSON
    protected_b64 = b64u(protected_json.encode('utf-8'))
    if kind == 'false':
        carried_payload = PAYLOAD.decode('utf-8')  # raw, unencoded text
        signing_input = protected_b64.encode('ascii') + b'.' + PAYLOAD
    else:
        carried_payload = b64u(PAYLOAD)        # base64url-encoded text
        signing_input = (protected_b64 + '.' + carried_payload).encode('ascii')
    mac = hmac.new(K, signing_input, hashlib.sha256).digest()
    return {
        'kind': kind,
        'protected_b64': protected_b64,
        'protected_json': protected_json,
        'carried_payload': carried_payload,
        'signature_b64': b64u(mac),
        'sig_bytes': mac,
        'signing_input': signing_input,
    }


def independent_mac_ok(sig):
    """Recompute MAC from original signing-input bytes; no string compare."""
    expect = hmac.new(K, sig['signing_input'], hashlib.sha256).digest()
    return hmac.compare_digest(expect, sig['sig_bytes'])


def library_matches_fixture(kind):
    """Cross-check: jwcrypto's own signer must emit the identical MAC."""
    from jwcrypto.jws import JWSCore
    hdr = variant_headers(kind)
    core = JWSCore('HS256', KEY, json_encode(hdr), PAYLOAD)
    out = core.sign()
    lib_mac = unb64u(out['signature'])
    return lib_mac == make_signature(kind)['sig_bytes']


def build_general_json(sigs, force_raw=False):
    # All entries share one payload member.
    if force_raw or sigs[0]['kind'] == 'false':
        carried = PAYLOAD.decode('utf-8')
    else:
        carried = sigs[0]['carried_payload']
    out = {'payload': carried, 'signatures': []}
    for s in sigs:
        entry = {'protected': s['protected_b64'],
                 'signature': s['signature_b64']}
        out['signatures'].append(entry)
    return json.dumps(out, separators=(',', ':'))


def run_case(kinds, force_raw=False):
    sigs = [make_signature(k) for k in kinds]
    # sanity: every carried signature is a valid MAC over its own input,
    # and jwcrypto's own signer produces the identical MAC bytes.
    assert all(independent_mac_ok(s) for s in sigs), 'fixture MAC invalid'
    assert all(library_matches_fixture(k) for k in kinds), \
        'fixture does not match library signer'
    raw = build_general_json(sigs, force_raw=force_raw)
    result = {
        'order': kinds,
        'all_fixtures_mac_valid': True,
        'deserialize_ok': None,
        'payload_bytes': None,
        'payload_matches_original': None,
        'verify_results': None,
        'reserialize_meaning': None,
        'error': None,
    }
    obj = jws.JWS()
    try:
        obj.deserialize(raw)
        result['deserialize_ok'] = True
        p = obj.objects.get('payload')
        if isinstance(p, str):
            p = p.encode('utf-8')
        result['payload_bytes'] = p
        result['payload_matches_original'] = (p == PAYLOAD)

        # Per-signature verification. Call the library's internal verifier
        # on each signature independently so a single failure cannot be
        # hidden by the "at least one valid" short-circuit in JWS.verify().
        per = []
        for entry, s in zip(obj.objects['signatures'], sigs):
            obj.verifylog = []
            try:
                obj._verify(None, KEY,
                            obj.objects['payload'],
                            entry['signature'],
                            entry.get('protected'),
                            entry.get('header'))
                lib_outcome = 'valid'
            except Exception as ve:  # noqa: BLE001
                lib_outcome = 'rejected:%s' % type(ve).__name__
            per.append({'kind': s['kind'],
                        'library_verify': lib_outcome,
                        'independent_mac_ok': independent_mac_ok(s)})
        result['verify_results'] = per

        # Re-serialization semantics of the *deserialized* object. The
        # library only emits signatures carrying an internal 'valid' flag,
        # which the plain deserialize() path does not set; record that
        # meaning explicitly instead of treating it as a payload issue.
        try:
            re = obj.serialize()
            rej = json.loads(re)
            result['reserialize_meaning'] = {
                'payload_member': rej.get('payload'),
                'n_signatures_emitted': len(rej.get('signatures', [])),
            }
        except Exception as se:  # noqa: BLE001
            result['reserialize_meaning'] = (
                'not-emitted(%s): deserialized signatures carry no'
                " 'valid' flag" % type(se).__name__)
    except Exception as de:  # noqa: BLE001
        result['deserialize_ok'] = False
        result['error'] = '%r' % (de,)
    return result


def fmt_verify(r):
    if not r['verify_results']:
        return 'n/a'
    return ','.join(v['library_verify'] for v in r['verify_results'])


def fmt_mac(r):
    if not r['verify_results']:
        return 'n/a'
    return ','.join(str(v['independent_mac_ok'])
                    for v in r['verify_results'])


def main():
    print('original application payload bytes:', PAYLOAD)
    print('=' * 78)
    matrix_a = [
        ('absent', 'absent'),
        ('absent', 'true'),
        ('true', 'absent'),
        ('true', 'true'),
    ]
    matrix_b = [
        ('false', 'true'),
        ('true', 'false'),
        ('false', 'absent'),
        ('absent', 'false'),
    ]

    rows = []
    print('MATRIX A — b64 default(absent) vs explicit true (all mean true)')
    for kinds in matrix_a:
        r = run_case(list(kinds))
        rows.append(('A', r))
        print(json.dumps(r, default=lambda o: repr(o), indent=2))
        print('-' * 78)

    print('MATRIX B — genuine b64 conflict (false vs true/absent)')
    for kinds in matrix_b:
        r = run_case(list(kinds), force_raw=True)
        rows.append(('B', r))
        print(json.dumps(r, default=lambda o: repr(o), indent=2))
        print('-' * 78)

    print('SUMMARY (library decision; independent MAC recomputation)')
    print('%-2s %-18s %-7s %-10s %-22s %-7s' % (
        'M', 'order', 'deser', 'payloadOK', 'per-sig library verify', 'macOK'))
    for matrix, r in rows:
        print('%-2s %-18s %-7s %-10s %-22s %-7s' % (
            matrix,
            '/'.join(r['order']),
            str(r['deserialize_ok']),
            str(r['payload_matches_original']),
            fmt_verify(r),
            fmt_mac(r)))


if __name__ == '__main__':
    main()
