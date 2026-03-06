# tests/test_did_key_agreement.py
"""Tests for keyAgreement in DID Documents."""

from __future__ import annotations

from polis_node.identity.did import PolisIdentity


class TestKeyAgreement:
    """Verify the X25519 keyAgreement entry in DID Documents."""

    def test_did_document_has_key_agreement(self) -> None:
        ident = PolisIdentity.create()
        doc = ident.to_did_document()
        assert "keyAgreement" in doc
        ka = doc["keyAgreement"]
        assert isinstance(ka, list)
        assert len(ka) == 1

    def test_key_agreement_type_and_controller(self) -> None:
        ident = PolisIdentity.create()
        doc = ident.to_did_document()
        entry = doc["keyAgreement"][0]
        assert entry["type"] == "X25519KeyAgreementKey2020"
        assert entry["controller"] == ident.did
        assert entry["id"] == f"{ident.did}#key-agreement"

    def test_key_agreement_has_public_key(self) -> None:
        ident = PolisIdentity.create()
        doc = ident.to_did_document()
        entry = doc["keyAgreement"][0]
        assert "publicKeyBase58" in entry
        assert len(entry["publicKeyBase58"]) > 0

    def test_key_agreement_differs_from_signing_key(self) -> None:
        ident = PolisIdentity.create()
        doc = ident.to_did_document()
        signing_key_b58 = doc["verificationMethod"][0]["publicKeyBase58"]
        ka_key_b58 = doc["keyAgreement"][0]["publicKeyBase58"]
        assert signing_key_b58 != ka_key_b58
