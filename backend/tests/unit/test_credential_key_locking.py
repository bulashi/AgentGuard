"""Lock-order source cases, authored without execution or collection.

All stored credentials, keys, verification steps and connections are synthetic.
These markers cannot establish signatures, real locks or revocation races.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import backend.delegation.verifier as verifier_module
from backend.common.error_codes import ReasonCode
from backend.delegation.verifier import ChainVerificationError, CredentialChainVerifier
from backend.identity.key_registry import KeyRegistryError


def _case(monkeypatch):
    chain = [
        SimpleNamespace(issuer_key_id="key-z", holder_key_id="key-a", signed_object={"fixture": "root"}),
        SimpleNamespace(issuer_key_id="key-a", holder_key_id="key-m", signed_object={"fixture": "middle"}),
        SimpleNamespace(issuer_key_id="key-m", holder_key_id="key-b", signed_object={"fixture": "leaf"}),
    ]
    events = []
    subject = CredentialChainVerifier("unit-only-chain", schema_store=Mock())
    load = Mock(side_effect=lambda *_args, **_kwargs: events.append("credentials") or chain)
    structure = Mock(side_effect=lambda *_args, **_kwargs: events.append("structure"))
    signatures = Mock(side_effect=lambda *_args, **_kwargs: events.append("signatures"))
    keys = Mock(side_effect=lambda _conn, key_id, **_kwargs: events.append(key_id))
    monkeypatch.setattr(subject, "_load_chain", load)
    monkeypatch.setattr(subject, "_verify_structure_and_links", structure)
    monkeypatch.setattr(subject, "_verify_signatures", signatures)
    monkeypatch.setattr(verifier_module.PostgresKeyRegistry, "get_with_connection", keys)
    return SimpleNamespace(
        subject=subject, connection=object(), chain=chain, events=events,
        load=load, structure=structure, signatures=signatures, keys=keys,
    )


def test_transactional_chain_locks_unique_keys_in_order_before_verification(monkeypatch) -> None:
    case = _case(monkeypatch)
    result = case.subject.verify_chain_with_connection(
        case.connection, "CRED-LEAF", current_time=100, lock=True,
    )
    assert result == [item.signed_object for item in case.chain]
    assert case.events == ["credentials", "key-a", "key-b", "key-m", "key-z", "structure", "signatures"]
    assert [call.args[1] for call in case.keys.call_args_list] == ["key-a", "key-b", "key-m", "key-z"]
    assert all(call.args[0] is case.connection and call.kwargs == {"lock": True}
               for call in case.keys.call_args_list)
    case.load.assert_called_once_with(case.connection, "CRED-LEAF", lock=True)


def test_readonly_chain_does_not_claim_or_acquire_admission_key_locks(monkeypatch) -> None:
    case = _case(monkeypatch)
    case.subject.verify_chain_with_connection(case.connection, "CRED-LEAF", current_time=100, lock=False)
    assert case.events == ["credentials", "structure", "signatures"]
    case.keys.assert_not_called()


def test_key_lock_resolution_failure_stops_before_structure_or_signature_checks(monkeypatch) -> None:
    case = _case(monkeypatch)
    error = KeyRegistryError(ReasonCode.UNKNOWN_KEY, "synthetic missing key")
    case.keys.side_effect = error
    with pytest.raises(ChainVerificationError) as captured:
        case.subject.verify_chain_with_connection(case.connection, "CRED-LEAF", current_time=100, lock=True)
    assert captured.value.reason_code is ReasonCode.UNKNOWN_KEY
    assert captured.value.__cause__ is error
    case.structure.assert_not_called()
    case.signatures.assert_not_called()
