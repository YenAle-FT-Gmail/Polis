"""Shared test fixtures."""

import pytest

import polis_node.api.app as _app_mod


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Clear the in-memory rate-limit buckets between every test."""
    _app_mod._RATE_BUCKETS.clear()
    yield
    _app_mod._RATE_BUCKETS.clear()
