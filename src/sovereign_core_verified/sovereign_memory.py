"""
sovereign_memory.py -- VERIFIED
Secure, memory-locked buffer for Ed25519 key material.
Uses the private nacl._sodium FFI layer because sodium_mlock/sodium_memzero/
sodium_munlock are NOT exposed on the public nacl.bindings surface (confirmed
by direct introspection: hasattr(nacl.bindings, 'sodium_mlock') == False).
"""
import sys
from nacl._sodium import lib as _sodium_lib
from nacl._sodium import ffi as _sodium_ffi

class SecureKeyBuffer:
    def __init__(self, size: int):
        self.size = size
        self._buf = bytearray(self.size)
        self.addr = _sodium_ffi.from_buffer(self._buf)
        self._locked = False
        if _sodium_lib.sodium_mlock(self.addr, self.size) != 0:
            sys.stderr.write("[SECURE_MEM_FATAL] sodium_mlock allocation failed.\n")
            sys.exit(1)
        self._locked = True

    def write_at_offset(self, data: bytes, offset: int = 0):
        if not self._locked:
            raise RuntimeError("Attempted write operation on an evicted memory buffer.")
        if offset + len(data) > self.size:
            raise ValueError("Data bounds exceed secure buffer allocation size.")
        self._buf[offset:offset+len(data)] = data

    def expose_raw_view(self) -> memoryview:
        if not self._locked:
            raise RuntimeError("Attempted read view operation on an evicted memory buffer.")
        return memoryview(self._buf)

    def clear(self):
        if self._locked:
            try:
                _sodium_lib.sodium_memzero(self.addr, self.size)
                _sodium_lib.sodium_munlock(self.addr, self.size)
            except Exception as e:
                sys.stderr.write(f"[SECURE_MEM_CRIT] {e}\n")
            finally:
                self._locked = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.clear()

    def __del__(self):
        self.clear()
