from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from backend.common.enums import KeyPurpose
from backend.crypto.canonical_json import CanonicalizationError, canonicalize
from backend.crypto.domains import HOLDER_PROOF
from backend.crypto.sm import sign_payload, signed_object_hash, sm3_hex, verify_payload

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def load_vector(name: str) -> dict:
    return json.loads((PROJECT_ROOT / "protocol/test-vectors" / name).read_text(encoding="utf-8"))


def test_canonical_and_sm3_vectors() -> None:
    document = load_vector("canonical-v1.json")
    for vector in document["vectors"]:
        output = canonicalize(vector["input"])
        assert output.decode("utf-8") == vector["expected_canonical_utf8"], vector["name"]
        assert sm3_hex(output) == vector["expected_sm3_hex"], vector["name"]


def test_official_sm3_vectors() -> None:
    document = load_vector("sm3-v1.json")
    for vector in document["vectors"]:
        assert sm3_hex(vector["message_utf8"].encode("utf-8")) == vector["expected_hex"]


def test_sm2_fixed_vector_and_negative_cases() -> None:
    vector = load_vector("sm2-v1.json")["vector"]
    signature = sign_payload(
        vector["payload"],
        domain_separator=vector["domain_separator"],
        key_id=vector["key_id"],
        key_purpose=KeyPurpose(vector["key_purpose"]),
        private_key_hex=vector["private_key_hex"],
        public_key_hex=vector["public_key_hex"],
        signed_at=vector["signed_at"],
        random_hex=vector["fixed_random_hex"],
    )
    assert signature["value"] == vector["expected_signature_hex"]
    signed = {"payload": vector["payload"], "signature": signature}
    assert signed_object_hash(signed) == vector["expected_signed_object_hash"]
    assert verify_payload(
        vector["payload"],
        signature,
        domain_separator=HOLDER_PROOF,
        expected_key_id=vector["key_id"],
        expected_key_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        public_key_hex=vector["public_key_hex"],
    )

    tampered = deepcopy(vector["payload"])
    tampered["request_id"] = "REQ-TAMPERED"
    assert not verify_payload(
        tampered,
        signature,
        domain_separator=HOLDER_PROOF,
        expected_key_id=vector["key_id"],
        expected_key_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        public_key_hex=vector["public_key_hex"],
    )
    assert not verify_payload(
        vector["payload"],
        signature,
        domain_separator="AGENTGUARD|EXECUTION_RECEIPT|V1",
        expected_key_id=vector["key_id"],
        expected_key_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        public_key_hex=vector["public_key_hex"],
    )
    assert not verify_payload(
        vector["payload"],
        signature,
        domain_separator=HOLDER_PROOF,
        expected_key_id=vector["key_id"],
        expected_key_purpose=KeyPurpose.EXECUTION_RECEIPT_SIGNING,
        public_key_hex=vector["public_key_hex"],
    )
    assert not verify_payload(
        vector["payload"],
        signature,
        domain_separator=HOLDER_PROOF,
        expected_key_id="wrong-key",
        expected_key_purpose=KeyPurpose.AGENT_HOLDER_SIGNING,
        public_key_hex=vector["public_key_hex"],
    )


def test_float_and_out_of_range_integer_are_not_canonicalizable() -> None:
    for value in ({"value": 1.25}, {"value": 9_007_199_254_740_992}):
        try:
            canonicalize(value)
        except CanonicalizationError:
            continue
        raise AssertionError(f"forbidden value canonicalized: {value}")
