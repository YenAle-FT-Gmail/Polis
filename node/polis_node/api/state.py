# polis/node/polis_node/api/state.py
"""
Polis Node shared application state.

Manages the DID resolver, storage backend, identity store, and record store.
Injected into routes via FastAPI's app.state.
"""

from __future__ import annotations

import base64
import json
from typing import Optional

import httpx
import structlog

from polis_node.config.settings import PolisNodeSettings
from polis_node.identity.did import DIDResolver, PolisIdentity
from polis_node.attribution.record import AttributionRecord
from polis_node.storage.interface import StorageBackend
from polis_node.storage.local import LocalStorageBackend


logger = structlog.get_logger(__name__)


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
        self.peers: list[str] = list(settings.peers)  # Mutable copy of initial peers

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

        Sets up the storage directory and initial peer connections.
        """
        logger.info(
            "node_state.initialize",
            node_id=self.settings.node_id,
            storage_backend=self.settings.storage_backend,
        )

    def register_identity(self, identity: PolisIdentity) -> None:
        """Register a new identity in the node state.

        Args:
            identity: The PolisIdentity to register.
        """
        self.identities[identity.did] = identity
        self.resolver.register(identity)
        logger.info("identity.registered", did=identity.did)

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

    def get_records_by_author(self, did: str) -> list[AttributionRecord]:
        """Get all records by a specific author DID.

        Args:
            did: The author's DID.

        Returns:
            List of AttributionRecords authored by the given DID.
        """
        return [r for r in self.records.values() if r.author_did == did]

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
                async with httpx.AsyncClient(
                    verify=scheme == "https", timeout=10.0
                ) as client:
                    resp = await client.post(url, json=payload)
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
