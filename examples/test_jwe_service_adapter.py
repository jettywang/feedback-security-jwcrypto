"""Contract tests for the JWE service-boundary adapter example.

Run explicitly:

    .venv/bin/python -m pytest -q examples/test_jwe_service_adapter.py
"""

import importlib.util
import json
import pathlib
import sys

import pytest

_PATH = pathlib.Path(__file__).with_name("jwe_service_adapter.py")
_SPEC = importlib.util.spec_from_file_location("jwe_service_adapter", _PATH)
adapter = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = adapter
_SPEC.loader.exec_module(adapter)

EXPECTED_SHAPE = {
    "error": {
        "code": adapter.PUBLIC_CODE,
        "message": adapter.PUBLIC_MESSAGE,
        "request_id": "<opaque>",
    }
}


def _shape(outcome):
    body = json.loads(json.dumps(outcome.body))
    body["error"]["request_id"] = "<opaque>"
    return body


@pytest.fixture(scope="module")
def fixtures():
    return adapter._fixtures()


def test_every_failure_has_one_public_reply(fixtures):
    for name, (token, key, expected) in fixtures.items():
        outcome = adapter.decrypt_request(token, key)
        if expected is None:
            assert outcome.ok, name
            assert outcome.plaintext == b"canary-plaintext", name
            continue

        assert not outcome.ok, name
        assert outcome.http_status == adapter.PUBLIC_STATUS, name
        assert _shape(outcome) == EXPECTED_SHAPE, name
        assert outcome.plaintext is None, name
        assert outcome.internal["reason"] == expected, name
        assert outcome.request_id in json.dumps(outcome.body), name
        assert outcome.request_id in json.dumps(outcome.internal), name


def test_internal_reasons_are_distinct(fixtures):
    reasons = {
        adapter.decrypt_request(token, key).internal["reason"]
        for token, key, expected in fixtures.values()
        if expected is not None
    }
    assert {
        adapter.REASON_KEY_NOT_FOUND,
        adapter.REASON_KEY_REJECTED,
        adapter.REASON_AUTHENTICATION,
        adapter.REASON_HEADER,
        adapter.REASON_PARSE,
        adapter.REASON_COMPRESSION,
        adapter.REASON_RESOURCE,
        adapter.REASON_EMPTY,
    } <= reasons


def test_prior_success_never_leaks_into_failure(fixtures):
    good, key, _ = fixtures["valid_control"]
    bad, _, _ = fixtures["corrupt_tag_gcm"]

    first = adapter.decrypt_request(good, key)
    assert first.ok and first.plaintext == b"canary-plaintext"

    second = adapter.decrypt_request(bad, key)
    assert not second.ok
    assert second.plaintext is None
    assert _shape(second) == EXPECTED_SHAPE
    assert second.request_id != first.request_id


def test_internal_text_is_scrubbed(fixtures):
    _, key, _ = fixtures["wrong_aes_private_key"]
    token, _, _ = fixtures["valid_control"]
    outcome = adapter.decrypt_request(token, key)
    joined = (outcome.internal["exception_text"]
              + outcome.internal["decrypt_log"])
    assert "BEGIN PRIVATE KEY" not in joined
    assert token not in joined


def test_internal_text_neutralizes_log_injection(fixtures):
    token, key, _ = fixtures["protected_non_utf8"]
    outcome = adapter.decrypt_request(token, key)
    for value in outcome.internal.values():
        if isinstance(value, str):
            assert "\n" not in value and "\r" not in value


def test_empty_plaintext_is_explicit_policy_not_a_generic_failure(fixtures):
    token, key, expected = fixtures["empty_plaintext_policy"]
    outcome = adapter.decrypt_request(token, key)
    assert not outcome.ok
    assert outcome.http_status == 400
    assert outcome.plaintext is None
    assert outcome.internal["reason"] == expected == adapter.REASON_EMPTY
    assert outcome.internal["stage"] == adapter.STAGE_POLICY
