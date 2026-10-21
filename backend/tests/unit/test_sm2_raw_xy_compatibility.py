from __future__ import annotations

from copy import deepcopy

import pytest

from backend.coauthorization.contracts import COAUTHORIZATION_DOMAIN
from backend.common.enums import KeyPurpose
from backend.crypto import sm
from backend.crypto.domains import HOLDER_PROOF
from backend.crypto.sm import (
    SM2_CURVE_ORDER,
    Sm2KeyPair,
    _sm2_context,
    derive_public_key,
    sign_message,
    sign_payload,
    verify_message,
    verify_payload,
)


@pytest.fixture(scope="module")
def raw_xy_starting_04() -> Sm2KeyPair:
    # Bounded deterministic test-only weak scalars, never deployment keys.
    # Derive with the existing library rather than inventing a public point.
    for scalar in range(1, 4097):
        private_key = f"{scalar:064x}"
        public_key = derive_public_key(private_key)
        if public_key.startswith("04"):
            return Sm2KeyPair(private_key_hex=private_key, public_key_hex=public_key)
    pytest.fail("no raw-XY prefix fixture found in the fixed scalar range; do not skip")


def test_context_keeps_full_raw_xy_encoding(raw_xy_starting_04: Sm2KeyPair) -> None:
    pair = raw_xy_starting_04
    context = _sm2_context(
        private_key_hex=pair.private_key_hex, public_key_hex=pair.public_key_hex
    )
    assert pair.public_key_hex.startswith("04")
    assert len(pair.public_key_hex) == 128
    assert context.public_key == pair.public_key_hex
    assert len(context.public_key) == 128


def test_real_message_signature_with_raw_xy_prefix(raw_xy_starting_04: Sm2KeyPair) -> None:
    pair = raw_xy_starting_04
    message = b"AgentGuard raw XY prefix regression, not a production credential"
    signature = sign_message(
        message, private_key_hex=pair.private_key_hex, public_key_hex=pair.public_key_hex
    )
    assert verify_message(message, signature, public_key_hex=pair.public_key_hex)
    assert not verify_message(message + b"-changed", signature, public_key_hex=pair.public_key_hex)
    wrong_scalar = int(pair.private_key_hex, 16) + 1
    wrong_public_key = derive_public_key(f"{wrong_scalar:064x}")
    assert wrong_public_key != pair.public_key_hex
    assert not verify_message(message, signature, public_key_hex=wrong_public_key)


@pytest.mark.parametrize("domain", [HOLDER_PROOF, COAUTHORIZATION_DOMAIN])
def test_real_payload_signature_and_domain_binding(
    raw_xy_starting_04: Sm2KeyPair, domain: str
) -> None:
    pair = raw_xy_starting_04
    payload = {"schema_version": "1.0", "task_id": "TASK-XY-PREFIX", "issued_at": 1800000120}
    signature = sign_payload(
        payload, domain_separator=domain, key_id="test-only-xy-key",
        key_purpose=KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
        private_key_hex=pair.private_key_hex, public_key_hex=pair.public_key_hex,
        signed_at=1800000120,
    )
    arguments = {
        "domain_separator": domain, "expected_key_id": "test-only-xy-key",
        "expected_key_purpose": KeyPurpose.AUTHORIZATION_ROOT_SIGNING,
        "public_key_hex": pair.public_key_hex,
    }
    assert verify_payload(payload, signature, **arguments)
    changed = deepcopy(payload)
    changed["task_id"] = "TASK-OTHER"
    assert not verify_payload(changed, signature, **arguments)
    arguments["domain_separator"] = "AGENTGUARD|EXECUTION_RECEIPT|V1"
    assert not verify_payload(payload, signature, **arguments)


@pytest.mark.parametrize(
    "public_key", ["", "04" + "1" * 128, "1" * 127, "G" * 128, "A" * 128]
)
def test_non_protocol_public_encoding_rejected(public_key: str) -> None:
    with pytest.raises(ValueError, match="raw XY"):
        _sm2_context(private_key_hex="", public_key_hex=public_key)
    assert not verify_message(b"encoding check", "1" * 128, public_key_hex=public_key)


def test_signing_key_generation_excludes_n_minus_one(monkeypatch: pytest.MonkeyPatch) -> None:
    samples = iter((f"{SM2_CURVE_ORDER - 1:064x}", "1".zfill(64)))
    monkeypatch.setattr(sm, "_valid_random_scalar", lambda: next(samples))
    pair = sm.generate_keypair()
    assert pair.private_key_hex == "1".zfill(64)
    assert pair.public_key_hex == derive_public_key(pair.private_key_hex)


@pytest.mark.parametrize("scalar", [0, SM2_CURVE_ORDER - 1, SM2_CURVE_ORDER])
def test_invalid_signing_scalar_rejected_before_library_use(
    scalar: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_context(**kwargs):
        pytest.fail("invalid signing scalar reached the crypto context")

    monkeypatch.setattr(sm, "_sm2_context", no_context)
    with pytest.raises(ValueError, match="private key scalar"):
        sign_message(
            b"invalid scalar", private_key_hex=f"{scalar:064x}",
            public_key_hex="1" * 128,
        )
