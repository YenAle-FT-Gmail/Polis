# polis/node/tests/test_main.py
"""Tests for __main__.py entry point."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

from polis_node.__main__ import main


class TestMain:
    """Tests for the main() entry point."""

    @patch("polis_node.__main__.uvicorn.run")
    @patch("polis_node.__main__.create_app")
    @patch("polis_node.__main__.PolisNodeSettings.from_env")
    def test_main_calls_uvicorn_run(
        self, mock_from_env: MagicMock, mock_create_app: MagicMock, mock_uvicorn_run: MagicMock
    ) -> None:
        """main() wires settings → create_app → uvicorn.run correctly."""
        mock_settings = MagicMock()
        mock_settings.host = "0.0.0.0"
        mock_settings.port = 8000
        mock_settings.log_level = "INFO"
        mock_from_env.return_value = mock_settings

        mock_app = MagicMock()
        mock_create_app.return_value = mock_app

        main()

        mock_from_env.assert_called_once()
        mock_create_app.assert_called_once_with(mock_settings)
        mock_uvicorn_run.assert_called_once_with(
            mock_app,
            host="0.0.0.0",
            port=8000,
            log_level="info",
        )
