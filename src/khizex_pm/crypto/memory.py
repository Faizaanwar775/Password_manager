"""
Best-effort in-memory secret zeroization.

CPython does not provide a hard guarantee that overwriting a
`bytearray` scrubs every copy of that data from process memory
(garbage collection, string interning, and OS paging can all leave
residue) -- but overwriting the buffer we control as soon as it is no
longer needed materially shrinks the window during which the raw key
or password is sitting in RAM, and is standard practice for this kind
of application. Wherever this project holds a derived key or a
plaintext secret, it is held as a `bytearray` (mutable) rather than
`bytes`/`str` (immutable) specifically so it can be zeroized here.
"""

from __future__ import annotations


def zero(buffer: bytearray) -> None:
    """Overwrite a mutable buffer in place with zero bytes."""
    for i in range(len(buffer)):
        buffer[i] = 0
