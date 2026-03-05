# polis/node/polis_node/__main__.py
"""
Polis Node entry point.

Starts the Polis node API server using uvicorn.
"""

import uvicorn

from polis_node.api.app import create_app
from polis_node.config.settings import PolisNodeSettings


def main() -> None:
    """Start the Polis node."""
    settings = PolisNodeSettings.from_env()
    app = create_app(settings)
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
