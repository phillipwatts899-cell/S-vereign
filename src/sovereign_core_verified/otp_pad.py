"""
otp_pad.py -- hardened

Local one-time-pad material store: generation, offset-tracked consumption,
tamper-evident journal persistence, and secure erasure.

Reuse-prevention invariant: the consumed-offset journal is written
atomically (temp file + os.replace) BEFORE reserve() returns pad bytes to
the caller.

Tamper-evidence invariant (this hardening pass): every journal write
includes a keyed BLAKE2b MAC over the offset, keyed from pad material that
never touches disk. On load, the MAC is recomputed and compared before the
offset is trusted. Any mismatch, corruption, or malformed journal fails
shut via CorruptJournalException -- construction of the store aborts
entirely, so no bytes can ever be issued from an unverified journal state.
"""
import os
import json
import hmac as _hmac_module  # for constant-time comparison only
import nacl.bindings
from nacl._sodium import lib as _sodium_lib
from nacl._sodium import ffi as _sodium_ffi

_MAC_PERSON = b"otp_journal_v1__"[:16]  # crypto_generichash person field is <=16 bytes
_MAC_DIGEST_SIZE = 32


class OTPExhaustedError(Exception):
    pass


class CorruptJournalException(Exception):
    """Raised when the on-disk journal is missing expected fields, malformed,
    or fails MAC verification. The store MUST NOT be constructed in this case --
    no pad bytes can be issued from an object that never finished __init__."""
    pass


def _compute_journal_mac(mac_key: bytes, offset: int) -> str:
    msg = f"consumed_offset={offset}".encode("ascii")
    digest = nacl.bindings.crypto_generichash_blake2b_salt_personal(
        msg, key=mac_key, digest_size=_MAC_DIGEST_SIZE, person=_MAC_PERSON
    )
    return digest.hex()


class OTPPadStore:
    def __init__(self, pad_size: int, journal_path: str, pad_material: bytes = None,
                 defer_fill: bool = False):
        self.pad_size = pad_size
        self.journal_path = journal_path
        self._buf = bytearray(pad_size)
        self._addr = _sodium_ffi.from_buffer(self._buf)
        if _sodium_lib.sodium_mlock(self._addr, pad_size) != 0:
            raise RuntimeError("sodium_mlock failed -- refusing to hold pad material in swappable memory")
        self._locked = True
        self._filled = False
        self._consumed_offset = None
        self._mac_key = None

        if defer_fill:
            if pad_material is not None:
                self.clear()
                raise ValueError("cannot specify both defer_fill=True and pad_material")
            # Buffer is allocated and locked, but left unfilled. No MAC key
            # derived, no journal touched. Caller (e.g. the ingestion bridge)
            # must populate self.addr / self.size externally (e.g. as the
            # decrypt target for open_sealed), then call finalize_fill().
            # Until finalize_fill() succeeds, reserve()/encrypt() refuse to
            # run, and no journal file for this journal_path is ever created.
            return

        try:
            if pad_material is not None:
                if len(pad_material) != pad_size:
                    raise ValueError("pad_material length does not match pad_size")
                self._buf[:] = pad_material
            else:
                _sodium_lib.randombytes(self._addr, pad_size)
            self._finalize_fill()
        except Exception:
            self.clear()
            raise

    @property
    def addr(self):
        """Raw locked-buffer pointer -- exposed so this store can itself be
        used as a decrypt target (e.g. otp_transport.open_sealed's out_buf
        parameter), avoiding any intermediate unprotected bytes copy."""
        return self._addr

    @property
    def size(self):
        return self.pad_size

    def _finalize_fill(self):
        self._mac_key = nacl.bindings.crypto_generichash_blake2b_salt_personal(
            bytes(self._buf), key=b"", digest_size=32, person=b"otp_mackey_v1__"[:16]
        )
        self._consumed_offset = self._load_journal()
        self._filled = True

    def finalize_fill(self):
        """Call after externally populating self.addr (defer_fill=True path
        only) -- e.g. immediately after open_sealed() has decrypted directly
        into this store's locked buffer. This is the single point at which
        a journal file may first be created for this journal_path. If this
        is never called (because an earlier pipeline step failed), no
        journal is ever written and the buffer should be cleared by the
        caller."""
        if self._filled:
            raise RuntimeError("finalize_fill() called on an already-finalized store")
        try:
            self._finalize_fill()
        except Exception:
            self.clear()
            raise

    def _require_filled(self):
        if not self._filled:
            raise RuntimeError(
                "OTPPadStore not finalized -- constructed with defer_fill=True "
                "but finalize_fill() was never called successfully"
            )

    def _load_journal(self) -> int:
        if not os.path.exists(self.journal_path):
            # Legitimate first run -- initialize fresh, at offset 0.
            offset = 0
            self._write_journal(offset)
            return offset

        try:
            with open(self.journal_path, "r") as f:
                raw = f.read()
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError) as e:
            raise CorruptJournalException(f"Journal unreadable or malformed: {e}") from e

        if "consumed_offset" not in data or "mac" not in data:
            raise CorruptJournalException(f"Journal missing required fields: {data!r}")

        offset = data["consumed_offset"]
        stored_mac = data["mac"]

        if not isinstance(offset, int) or not (0 <= offset <= self.pad_size):
            raise CorruptJournalException(
                f"consumed_offset {offset!r} out of bounds for pad_size {self.pad_size}"
            )

        expected_mac = _compute_journal_mac(self._mac_key, offset)
        if not _hmac_module.compare_digest(expected_mac, stored_mac):
            raise CorruptJournalException(
                "Journal MAC verification failed -- offset may have been tampered with "
                "or rolled back. Refusing to trust this journal."
            )

        return offset

    def _write_journal(self, offset: int) -> None:
        mac = _compute_journal_mac(self._mac_key, offset)
        tmp_path = self.journal_path + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump({"consumed_offset": offset, "mac": mac}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, self.journal_path)

    def remaining(self) -> int:
        self._require_filled()
        return self.pad_size - self._consumed_offset

    def reserve(self, n: int) -> tuple:
        self._require_filled()
        if n <= 0:
            raise ValueError("n must be positive")
        if n > self.remaining():
            raise OTPExhaustedError(
                f"Requested {n} bytes but only {self.remaining()} remain (pad_size={self.pad_size})"
            )
        offset = self._consumed_offset
        new_offset = offset + n
        self._write_journal(new_offset)
        self._consumed_offset = new_offset
        pad_slice = bytes(self._buf[offset:offset + n])
        return offset, pad_slice

    def reserve_into(self, n: int, dest_addr, dest_offset: int = 0) -> int:
        """Same atomicity invariant as reserve() (journal written BEFORE
        bytes become usable -- a crash after this call burns the bytes
        rather than risking reuse), but copies the reserved pad slice
        DIRECTLY into dest_addr via ffi.memmove. No Python bytes/bytearray
        copy of the plaintext pad is ever created. dest_addr must be a raw
        cffi pointer (e.g. another SecureKeyBuffer's .addr). Returns the
        source offset the reservation started at."""
        self._require_filled()
        if n <= 0:
            raise ValueError("n must be positive")
        if n > self.remaining():
            raise OTPExhaustedError(
                f"Requested {n} bytes but only {self.remaining()} remain (pad_size={self.pad_size})"
            )
        offset = self._consumed_offset
        new_offset = offset + n
        self._write_journal(new_offset)   # atomic, BEFORE the memmove -- same burn-on-crash guarantee as reserve()
        self._consumed_offset = new_offset

        src_ptr = _sodium_ffi.cast("unsigned char *", self._addr) + offset
        dst_ptr = _sodium_ffi.cast("unsigned char *", dest_addr) + dest_offset
        _sodium_ffi.memmove(dst_ptr, src_ptr, n)
        return offset

    def encrypt(self, plaintext: bytes) -> tuple:
        offset, pad_bytes = self.reserve(len(plaintext))
        ciphertext = bytes(p ^ k for p, k in zip(plaintext, pad_bytes))
        return offset, ciphertext

    @staticmethod
    def decrypt(ciphertext: bytes, pad_bytes: bytes) -> bytes:
        if len(ciphertext) != len(pad_bytes):
            raise ValueError("ciphertext/pad length mismatch")
        return bytes(c ^ k for c, k in zip(ciphertext, pad_bytes))

    def clear(self):
        if getattr(self, "_locked", False):
            _sodium_lib.sodium_memzero(self._addr, self.pad_size)
            _sodium_lib.sodium_munlock(self._addr, self.pad_size)
            self._locked = False

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.clear()

    def __del__(self):
        self.clear()
