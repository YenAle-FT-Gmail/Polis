# polis/node/polis_node/identity/secure_bytes.py
"""
Secure bytes container for private key material.

Provides a wrapper that attempts to zero memory when no longer needed,
reducing the window of exposure for private keys in memory.

This is a best-effort defense-in-depth measure.  Python does not
guarantee control over memory layout, but zeroing the internal buffer
on ``__del__`` / ``clear()`` meaningfully reduces the risk of key
material surviving in process memory.
"""

from __future__ import annotations

import ctypes


class SecureBytes:
    """A bytes-like container that zeros its contents when destroyed.

    Usage::

        key = SecureBytes(raw_key_bytes)
        # use key.value for operations
        key.clear()  # explicitly zero, or let __del__ handle it

    Attributes:
        _buf: Internal mutable buffer holding the key material.
    """

    __slots__ = ("_buf",)

    def __init__(self, data: bytes) -> None:
        """Initialize with key material.

        Args:
            data: The raw bytes to protect.
        """
        self._buf: bytearray = bytearray(data)

    @property
    def value(self) -> bytes:
        """Return the contained bytes.

        Returns:
            The key material as immutable bytes.

        Raises:
            ValueError: If the buffer has been cleared.
        """
        if not self._buf:
            raise ValueError("SecureBytes has been cleared")
        return bytes(self._buf)

    def clear(self) -> None:
        """Zero and discard the buffer contents."""
        if self._buf:
            # Zero the buffer in-place
            buf_len = len(self._buf)
            ctypes.memset(
                (ctypes.c_char * buf_len).from_buffer(self._buf),
                0,
                buf_len,
            )
            self._buf = bytearray()

    def __del__(self) -> None:
        """Zero memory on garbage collection."""
        self.clear()

    def __len__(self) -> int:
        return len(self._buf)

    def __bool__(self) -> bool:
        return bool(self._buf)

    def __repr__(self) -> str:
        return f"SecureBytes(<{len(self._buf)} bytes>)"
