# polis/node/polis_node/api/state.py
"""
Polis Node shared application state.

Manages the DID resolver, storage backend, identity store, and record store.
Injected into routes via FastAPI's app.state.
"""

from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from typing import Optional

import httpx
import structlog

from polis_node.config.settings import PolisNodeSettings
from polis_node.identity.did import DIDResolver, PolisIdentity
from polis_node.identity.persistence import save_identity, load_identity
from polis_node.attribution.record import AttributionRecord, PermissionToken
from polis_node.storage.interface import StorageBackend
from polis_node.storage.local import LocalStorageBackend
from polis_node.moderation.engine import ModerationEngine


logger = structlog.get_logger(__name__)

# Maximum payload size in bytes (10 MiB)
MAX_PAYLOAD_SIZE: int = 10 * 1024 * 1024

# Default page size for paginated endpoints
DEFAULT_PAGE_SIZE: int = 50
MAX_PAGE_SIZE: int = 200


class NodeState:
    """Shared state for the Polis node.

    Holds the DID resolver, storage backend, and in-memory stores
    for identities and attribution records.

    Attributes:
        settings: Node configuration.
        resolver: DID resolver for looking up identities.
        storage: Active storage backend.
        identities: Mapping of DID -> PolisIdentity (in-memory for v0.1).
        records: Mapping of CID -> AttributionRecord (in-memory index).
        moderation: Content moderation engine.
    """

    def __init__(self, settings: PolisNodeSettings) -> None:
        """Initialize node state.

        Args:
            settings: The node configuration.
        """
        self.settings = settings
        self.resolver = DIDResolver()
        self.storage: StorageBackend = self._create_storage_backend()
        self.identities: dict[str, PolisIdentity] = {}
        self.records: dict[str, AttributionRecord] = {}
        self.record_data: dict[str, bytes] = {}  # CID -> raw payload/ciphertext
        self.permission_token_objects: dict[str, PermissionToken] = {}  # token_id -> PermissionToken
        self.peers: list[str] = list(settings.peers)  # Mutable copy of initial peers
        self.moderation = ModerationEngine()
        self._started_at: float = time.monotonic()

    def _create_storage_backend(self) -> StorageBackend:
        """Create the storage backend based on configuration.

        Returns:
            A StorageBackend instance.

        Raises:
            ValueError: If the configured backend is not supported.
        """
        backend_type = self.settings.storage_backend.lower()

        if backend_type == "local":
            return LocalStorageBackend(self.settings.data_dir)
        elif backend_type == "ipfs":
            from polis_node.storage.ipfs import IPFSBackend
            return IPFSBackend(self.settings.ipfs_api_url)
        elif backend_type == "arweave":
            from polis_node.storage.arweave import ArweaveBackend
            return ArweaveBackend(self.settings.arweave_gateway_url)
        else:
            raise ValueError(
                f"Unsupported storage backend: '{backend_type}'. "
                f"Supported: local, ipfs, arweave"
            )

    async def initialize(self) -> None:
        """Initialize the node state (called during application startup).

        Loads persisted identities and records from disk and sets up storage.
        """
        logger.info(
            "node_state.initialize",
            node_id=self.settings.node_id,
            storage_backend=self.settings.storage_backend,
        )
        self._started_at = time.monotonic()
        # Warn if identity passphrase is empty
        if not self.settings.identity_passphrase:
            logger.warning(
                "node_state.empty_passphrase",
                msg=(
                    "POLIS_IDENTITY_PASSPHRASE is not set. "
                    "Identities will NOT be persisted across restarts. "
                    "Set a strong passphrase in production."
                ),
            )
        # Load persisted identities from encrypted files
        self._load_persisted_identities()
        # Load persisted records
        self._load_persisted_records()

    async def shutdown(self) -> None:
        """Graceful shutdown — persist state before exit."""
        logger.info("node_state.shutdown", identity_count=len(self.identities))
        self._persist_identities()
        self._persist_records()

    def _load_persisted_identities(self) -> None:
        """Load all encrypted identity files from POLIS_IDENTITY_DIR."""
        identity_dir = Path(self.settings.identity_dir)
        if not identity_dir.exists():
            return
        passphrase = self.settings.identity_passphrase
        if not passphrase:
            logger.warning("node_state.no_passphrase", msg="POLIS_IDENTITY_PASSPHRASE not set; skipping identity restore")
            return
        for fp in identity_dir.glob("*.json"):
            try:
                ident = load_identity(fp, passphrase)
                self.identities[ident.did] = ident
                self.resolver.register(ident)
                logger.info("identity.restored", did=ident.did)
            except Exception as exc:
                logger.error("identity.restore_failed", path=str(fp), error=str(exc))

    def _persist_identities(self) -> None:
        """Persist all identities as encrypted files."""
        passphrase = self.settings.identity_passphrase
        if not passphrase:
            logger.warning("node_state.no_passphrase", msg="Skipping identity persistence")
            return
        identity_dir = Path(self.settings.identity_dir)
        identity_dir.mkdir(parents=True, exist_ok=True)
        for did, ident in self.identities.items():
            try:
                fp = identity_dir / f"{did.replace(':', '_')}.json"
                save_identity(ident, fp, passphrase)
            except Exception as exc:
                logger.error("identity.persist_failed", did=did, error=str(exc))

    # ------------------------------------------------------------------
    # Record persistence
    # ------------------------------------------------------------------

    def _load_persisted_records(self) -> None:
        """Load persisted records and their data from disk."""
        records_dir = Path(self.settings.data_dir) / "records"
        if not records_dir.exists():
            return
        for meta_fp in records_dir.glob("*.meta.json"):
            try:
                meta = json.loads(meta_fp.read_text(encoding="utf-8"))
                record = AttributionRecord.from_dict(meta)
                data_fp = meta_fp.with_suffix("").with_suffix(".data")
                if data_fp.exists():
                    payload = base64.b64decode(data_fp.read_text(encoding="utf-8"))
                else:
                    payload = b""
                self.records[record.cid] = record
                self.record_data[record.cid] = payload
                logger.info("record.restored", cid=record.cid)
            except Exception as exc:
                logger.error("record.restore_failed", path=str(meta_fp), error=str(exc))

    def _persist_records(self) -> None:
        """Persist all records and their data to disk."""
        records_dir = Path(self.settings.data_dir) / "records"
        records_dir.mkdir(parents=True, exist_ok=True)
        for cid, record in self.records.items():
            try:
                safe_cid = cid.replace("/", "_")
                meta_fp = records_dir / f"{safe_cid}.meta.json"
                meta_fp.write_text(
                    json.dumps(record.to_dict()), encoding="utf-8"
                )
                data_fp = records_dir / f"{safe_cid}.data"
                payload = self.record_data.get(cid, b"")
                data_fp.write_text(
                    base64.b64encode(payload).decode("ascii"), encoding="utf-8"
                )
            except Exception as exc:
                logger.error("record.persist_failed", cid=cid, error=str(exc))

    def register_identity(self, identity: PolisIdentity) -> None:
        """Register a new identity in the node state.

        Args:
            identity: The PolisIdentity to register.
        """
        self.identities[identity.did] = identity
        self.resolver.register(identity)
        logger.info("identity.registered", did=identity.did)

    def store_permission_token(self, token: PermissionToken) -> None:
        """Store a permission token object for later retrieval.

        Args:
            token: The PermissionToken to store.
        """
        self.permission_token_objects[token.token_id] = token

    def get_permission_token(self, token_id: str) -> Optional[PermissionToken]:
        """Look up a permission token by ID.

        Args:
            token_id: The token identifier.

        Returns:
            The PermissionToken if found, None otherwise.
        """
        return self.permission_token_objects.get(token_id)

    def get_identity(self, did: str) -> Optional[PolisIdentity]:
        """Look up an identity by DID.

        Args:
            did: The DID to look up.

        Returns:
            The PolisIdentity if found, None otherwise.
        """
        return self.identities.get(did)

    async def store_record(
        self, record: AttributionRecord, payload_data: bytes
    ) -> None:
        """Store an attribution record and its payload data.

        Args:
            record: The signed AttributionRecord.
            payload_data: The raw data (or ciphertext for private records).
        """
        # Store raw data in the storage backend
        await self.storage.put(payload_data)

        # Index the record in memory
        self.records[record.cid] = record
        self.record_data[record.cid] = payload_data

        # Also store the record metadata itself
        record_json = json.dumps(record.to_dict()).encode("utf-8")
        await self.storage.put(record_json)

        logger.info(
            "record.stored",
            cid=record.cid,
            author_did=record.author_did,
            visibility=record.visibility,
        )

    def get_record(self, cid: str) -> Optional[AttributionRecord]:
        """Look up a record by CID.

        Args:
            cid: The content identifier.

        Returns:
            The AttributionRecord if found, None otherwise.
        """
        return self.records.get(cid)

    def get_records_by_author(
        self, did: str, *, offset: int = 0, limit: int = DEFAULT_PAGE_SIZE
    ) -> list[AttributionRecord]:
        """Get paginated records by a specific author DID.

        Args:
            did: The author's DID.
            offset: Number of records to skip.
            limit: Maximum number of records to return.

        Returns:
            List of AttributionRecords authored by the given DID.
        """
        limit = min(limit, MAX_PAGE_SIZE)
        all_records = [r for r in self.records.values() if r.author_did == did]
        return all_records[offset : offset + limit]

    def get_health_status(self) -> dict:
        """Assess actual node health.

        Returns:
            A dict with status, uptime, and component checks.
        """
        uptime = time.monotonic() - self._started_at
        storage_ok = self.storage is not None
        identity_count = len(self.identities)
        record_count = len(self.records)

        status = "healthy"
        if not storage_ok:
            status = "degraded"
        if identity_count == 0 and record_count == 0 and uptime > 60:
            status = "idle"

        return {
            "status": status,
            "uptime_seconds": round(uptime, 1),
            "storage_ok": storage_ok,
            "identity_count": identity_count,
            "record_count": record_count,
            "peer_count": len(self.peers),
        }

    async def propagate_record(
        self, record: AttributionRecord, storable_data: bytes
    ) -> dict[str, str]:
        """Propagate a record to all known peers via the /ingest endpoint.

        Best-effort: failures on individual peers are logged but do not
        prevent propagation to other peers.

        Args:
            record: The signed AttributionRecord to propagate.
            storable_data: The raw data associated with the record.

        Returns:
            A dict mapping peer address to status ("ok" / error message).
        """
        if not self.peers:
            return {}

        results: dict[str, str] = {}
        payload = {
            "record": record.to_dict(),
            "data": base64.b64encode(storable_data).decode("ascii"),
        }

        for peer in list(self.peers):
            # Use http for dev nodes, https otherwise (matches node.py logic)
            scheme = (
                "http"
                if self.settings.node_id.startswith("dev-")
                else "https"
            )
            url = f"{scheme}://{peer}/records/ingest"
            try:
                headers = self._make_signed_headers("POST", url)
                async with httpx.AsyncClient(
                    verify=scheme == "https", timeout=10.0
                ) as client:
                    resp = await client.post(url, json=payload, headers=headers)
                    if resp.status_code == 200:
                        results[peer] = "ok"
                    else:
                        results[peer] = f"http_{resp.status_code}"
            except Exception as exc:
                logger.warning(
                    "propagation.failed",
                    peer=peer,
                    cid=record.cid,
                    error=str(exc),
                )
                results[peer] = f"error: {exc}"

        return results

    # ------------------------------------------------------------------
    # Inter-node request signing helpers
    # ------------------------------------------------------------------

    def _make_signed_headers(self, method: str, url: str) -> dict[str, str]:
        """Create signed headers for outgoing inter-node requests (Inv 21)."""
        if not self.identities:
            return {}
        node_identity = next(iter(self.identities.values()))
        ts = str(int(time.time()))
        message = f"{method}|{url}|{ts}".encode("utf-8")
        signature = node_identity.sign(message)
        return {
            "X-Polis-Node-DID": node_identity.did,
            "X-Polis-Timestamp": ts,
            "X-Polis-Signature": signature.hex(),
        }

    def verify_inter_node_signature(
        self,
        method: str,
        url: str,
        node_did: str,
        timestamp: str,
        signature_hex: str,
        *,
        max_age_seconds: int = 300,
    ) -> bool:
        """Verify a signed inter-node request (Invariant 21).

        Args:
            method: HTTP method.
            url: The target URL.
            node_did: The claiming node's DID.
            timestamp: Unix timestamp string from the header.
            signature_hex: Hex-encoded Ed25519 signature.
            max_age_seconds: Maximum age of the timestamp (replay window).

        Returns:
            True if the signature is valid and fresh, False otherwise.
        """
        # Replay protection: reject stale timestamps
        try:
            ts = int(timestamp)
        except (ValueError, TypeError):
            return False
        if abs(time.time() - ts) > max_age_seconds:
            return False

        # Resolve the signing public key for the node DID
        pub_key_bytes = self.resolver.get_signing_public_key(node_did)
        if pub_key_bytes is None:
            return False

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        message = f"{method}|{url}|{timestamp}".encode("utf-8")
        try:
            pub = Ed25519PublicKey.from_public_bytes(pub_key_bytes)
            pub.verify(bytes.fromhex(signature_hex), message)
            return True
        except Exception:
            return False
