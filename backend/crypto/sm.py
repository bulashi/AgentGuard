from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from typing import Any

from gmssl import sm2

from backend.common.enums import KeyPurpose
from backend.crypto.canonical_json import canonicalize

SM2_USER_ID_UTF8 = "1234567812345678"
SM2_SIGNATURE_ENCODING = "SM2_RS_HEX_128_LOWERCASE"
SM2_CURVE_ORDER = int(sm2.default_ecc_table["n"], 16)


@dataclass(frozen=True)
class Sm2KeyPair:
    private_key_hex: str
    public_key_hex: str


def sm3_bytes(data: bytes) -> bytes:
    return hashlib.new("sm3", data).digest()


def sm3_hex(data: bytes) -> str:
    return hashlib.new("sm3", data).hexdigest()


def domain_message(domain_separator: str, payload: Any) -> bytes:
    if not domain_separator.startswith("AGENTGUARD|"):
        raise ValueError("domain separator is not an AgentGuard domain")
    return domain_separator.encode("utf-8") + b"\x00" + canonicalize(payload)


def _valid_random_scalar() -> str:
    while True:
        value = secrets.randbelow(SM2_CURVE_ORDER - 1) + 1
        if 1 <= value < SM2_CURVE_ORDER:
            return f"{value:064x}"


def derive_public_key(private_key_hex: str) -> str:
    if len(private_key_hex) != 64:
        raise ValueError("SM2 private key must be 32 bytes")
    private_value = int(private_key_hex, 16)
    if not 1 <= private_value < SM2_CURVE_ORDER:
        raise ValueError("SM2 private key scalar is out of range")
    signer = sm2.CryptSM2(private_key=private_key_hex, public_key="")
    return signer._kg(private_value, sm2.default_ecc_table["g"]).lower()


def generate_keypair() -> Sm2KeyPair:
    private_key_hex = _valid_random_scalar()
    # Signing needs (d + 1)^-1 modulo n; the nonce range also contains n - 1.
    while int(private_key_hex, 16) == SM2_CURVE_ORDER - 1:
        private_key_hex = _valid_random_scalar()
    return Sm2KeyPair(
        private_key_hex=private_key_hex,
        public_key_hex=derive_public_key(private_key_hex),
    )


def _sm2_context(*, private_key_hex: str, public_key_hex: str) -> sm2.CryptSM2:
    if (
        not isinstance(public_key_hex, str)
        or re.fullmatch(r"[0-9a-f]{128}", public_key_hex) is None
    ):
        raise ValueError("SM2 public key must be 128 lowercase raw XY hexadecimal characters")
    # gmssl 3.2.2 lstrip("04") can remove real X-coordinate bytes. The frozen
    # protocol uses raw XY, not a SEC1 prefix; preserve all 128 characters.
    context = sm2.CryptSM2(private_key=private_key_hex, public_key="", asn1=False)
    context.public_key = public_key_hex
    return context


def sign_message(
    message: bytes,
    *,
    private_key_hex: str,
    public_key_hex: str,
    random_hex: str | None = None,
) -> str:
    if (
        not isinstance(private_key_hex, str)
        or re.fullmatch(r"[0-9a-f]{64}", private_key_hex) is None
        or not 1 <= int(private_key_hex, 16) < SM2_CURVE_ORDER - 1
    ):
        raise ValueError("invalid SM2 signing private key scalar")
    signer = _sm2_context(private_key_hex=private_key_hex, public_key_hex=public_key_hex)
    signature = signer.sign_with_sm3(message, random_hex or _valid_random_scalar())
    if len(signature) != 128:
        raise ValueError("unexpected SM2 signature encoding")
    return signature.lower()


def verify_message(message: bytes, signature_hex: str, *, public_key_hex: str) -> bool:
    if len(signature_hex) != 128:
        return False
    try:
        verifier = _sm2_context(private_key_hex="", public_key_hex=public_key_hex)
        return bool(verifier.verify_with_sm3(signature_hex, message))
    except (TypeError, ValueError, IndexError):
        return False


def sign_payload(
    payload: Any,
    *,
    domain_separator: str,
    key_id: str,
    key_purpose: KeyPurpose,
    private_key_hex: str,
    public_key_hex: str,
    signed_at: int,
    random_hex: str | None = None,
) -> dict[str, Any]:
    message = domain_message(domain_separator, payload)
    return {
        "algorithm": "SM2",
        "key_id": key_id,
        "key_purpose": key_purpose.value,
        "encoding": SM2_SIGNATURE_ENCODING,
        "value": sign_message(
            message,
            private_key_hex=private_key_hex,
            public_key_hex=public_key_hex,
            random_hex=random_hex,
        ),
        "signed_at": signed_at,
    }


def verify_payload(
    payload: Any,
    signature: dict[str, Any],
    *,
    domain_separator: str,
    expected_key_id: str,
    expected_key_purpose: KeyPurpose,
    public_key_hex: str,
) -> bool:
    if signature.get("algorithm") != "SM2":
        return False
    if signature.get("encoding") != SM2_SIGNATURE_ENCODING:
        return False
    if signature.get("key_id") != expected_key_id:
        return False
    if signature.get("key_purpose") != expected_key_purpose.value:
        return False
    value = signature.get("value")
    if not isinstance(value, str):
        return False
    return verify_message(
        domain_message(domain_separator, payload),
        value,
        public_key_hex=public_key_hex,
    )


def signed_object_hash(signed_object: dict[str, Any]) -> str:
    return sm3_hex(canonicalize(signed_object))
