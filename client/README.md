# Polis Client SDK

Python client library for interacting with the Polis decentralised protocol.

## Installation

```bash
pip install polis-client
# or
poetry add polis-client
```

## Quick Start

```python
import asyncio
from polis_client import PolisClient

async def main():
    async with PolisClient("http://localhost:8000") as client:
        # Create an identity
        identity = await client.create_identity()
        print(f"DID: {identity['did']}")

        # Create a record
        record = await client.create_record(
            payload=b"Hello, Polis!",
            author_did=identity["did"],
        )
        print(f"CID: {record['cid']}")

        # Retrieve a record
        fetched = await client.get_record(record["cid"])
        print(fetched)

asyncio.run(main())
```

## API Reference

See the full API docs at your node's `/docs` endpoint (Swagger UI).

## License

MIT — see [LICENSE](../LICENSE).
