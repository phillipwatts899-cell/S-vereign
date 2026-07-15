"""
otp_transport.py -- Phase 1: keypair handling + sealed packing.

Built exclusively against the private nacl._sodium FFI (pointer-based) layer
for any operation touching private key material or plaintext pad content.
The public nacl.bindings.crypto_box_seal/_open take plain `bytes`, which
would force an intermediate unprotected heap copy of secret material --
the exact Defect 109 pattern already eliminated from the key ceremony.

Ciphertext output IS allowed to live in ordinary (non-locked) memory: its
confidentiality is guaranteed by the cryptography itself, not by memory
protection, since it's the artifact meant to cross an untrusted channel.
Only plaintext pad material and secret keys require locked buffers.
"""
import sys
import nacl.bindings
from nacl._sodium import lib as _sodium_lib
from nacl._sodium import ffi as _sodium_ffi
from sovereign_memory import SecureKeyBuffer

BOX_PUBLICKEYBYTES = nacl.bindings.crypto_box_PUBLICKEYBYTES
BOX_SECRETKEYBYTES = nacl.bindings.crypto_box_SECRETKEYBYTES
BOX_SEALBYTES = nacl.bindings.crypto_box_SEALBYTES


class SealFailedError(Exception):
    pass


def generate_box_keypair():
    """Generates a Curve25519 keypair directly into locked buffers via the
    raw FFI -- no seed, no intermediate Python bytes object at any point."""
    pk_buf = SecureKeyBuffer(BOX_PUBLICKEYBYTES)
    sk_buf = SecureKeyBuffer(BOX_SECRETKEYBYTES)
    rc = _sodium_lib.crypto_box_keypair(pk_buf.addr, sk_buf.addr)
    if rc != 0:
        pk_buf.clear()
        sk_buf.clear()
        raise RuntimeError(f"crypto_box_keypair failed, rc={rc}")
    return pk_buf, sk_buf


def seal_pad(plaintext_buf: SecureKeyBuffer, plaintext_len: int, recipient_pk: bytes) -> bytes:
    """Encrypts plaintext_len bytes read DIRECTLY from plaintext_buf's locked
    address against recipient_pk. Returns ciphertext as ordinary bytes --
    safe, since ciphertext confidentiality comes from the algorithm, not
    from memory locking."""
    if plaintext_len > plaintext_buf.size:
        raise ValueError("plaintext_len exceeds buffer size")
    if len(recipient_pk) != BOX_PUBLICKEYBYTES:
        raise ValueError(f"recipient_pk must be {BOX_PUBLICKEYBYTES} bytes")

    ciphertext = bytearray(plaintext_len + BOX_SEALBYTES)
    ct_addr = _sodium_ffi.from_buffer(ciphertext)
    pk_bytearray = bytearray(recipient_pk)  # mutable copy for from_buffer; pk is public, not secret
    pk_addr = _sodium_ffi.from_buffer(pk_bytearray)

    rc = _sodium_lib.crypto_box_seal(ct_addr, plaintext_buf.addr, plaintext_len, pk_addr)
    if rc != 0:
        raise SealFailedError(f"crypto_box_seal failed, rc={rc}")
    return bytes(ciphertext)


def open_sealed(ciphertext: bytes, recipient_pk_buf: SecureKeyBuffer,
                 recipient_sk_buf: SecureKeyBuffer, out_buf: SecureKeyBuffer) -> int:
    """Decrypts ciphertext DIRECTLY into out_buf's locked address. Returns
    the plaintext length (caller must only trust out_buf[:return_value]).
    Raises SealFailedError on authentication failure, corrupt ciphertext,
    or wrong keypair -- never silently returns garbage plaintext."""
    pt_len = len(ciphertext) - BOX_SEALBYTES
    if pt_len < 0:
        raise ValueError("ciphertext shorter than BOX_SEALBYTES -- not a valid sealed box")
    if pt_len > out_buf.size:
        raise ValueError(f"decrypted plaintext ({pt_len} bytes) exceeds out_buf size ({out_buf.size})")

    ct_bytearray = bytearray(ciphertext)
    ct_addr = _sodium_ffi.from_buffer(ct_bytearray)

    rc = _sodium_lib.crypto_box_seal_open(
        out_buf.addr, ct_addr, len(ciphertext), recipient_pk_buf.addr, recipient_sk_buf.addr
    )
    if rc != 0:
        raise SealFailedError(
            "crypto_box_seal_open failed -- authentication failure, tampered "
            "ciphertext, or wrong recipient keypair. Refusing to trust output."
        )
    return pt_len


# ---------------------------------------------------------------------------
# Phase 1b: Ed25519 signing wrapper over sealed ciphertext.
#
# The raw FFI exposes only COMBINED-mode signing (crypto_sign / crypto_sign_open)
# -- signature prepended to a copy of the message -- not detached-mode, which
# doesn't exist at this layer. That's fine here: the "message" being signed is
# the sealed ciphertext, which is not secret (its confidentiality comes from
# crypto_box_seal, not from memory locking), so combined mode's copy-the-message
# behavior costs nothing. What DOES matter is that the secret SIGNING key never
# leaves its locked buffer as a Python bytes object -- the public
# nacl.bindings.crypto_sign_detached would force exactly that violation via its
# sk: bytes parameter, so it's excluded here for the same reason crypto_box_seal
# was excluded from the public API in Phase 1.
# ---------------------------------------------------------------------------

SIGN_PUBLICKEYBYTES = nacl.bindings.crypto_sign_PUBLICKEYBYTES
SIGN_SECRETKEYBYTES = nacl.bindings.crypto_sign_SECRETKEYBYTES
SIGN_BYTES = nacl.bindings.crypto_sign_BYTES


class SignatureVerificationError(Exception):
    pass


def generate_sign_keypair():
    """Ed25519 identity keypair, generated directly into locked buffers via
    the raw FFI crypto_sign_keypair -- no seed, no intermediate bytes."""
    pk_buf = SecureKeyBuffer(SIGN_PUBLICKEYBYTES)
    sk_buf = SecureKeyBuffer(SIGN_SECRETKEYBYTES)
    rc = _sodium_lib.crypto_sign_keypair(pk_buf.addr, sk_buf.addr)
    if rc != 0:
        pk_buf.clear()
        sk_buf.clear()
        raise RuntimeError(f"crypto_sign_keypair failed, rc={rc}")
    return pk_buf, sk_buf


def sign_and_wrap(ciphertext: bytes, sender_sk_buf: SecureKeyBuffer) -> bytes:
    """Signs ciphertext (not secret -- ordinary bytes input is fine) using
    the sender's secret signing key read DIRECTLY from its locked address.
    Returns signature||ciphertext as ordinary bytes (safe to transmit)."""
    if sender_sk_buf.size != SIGN_SECRETKEYBYTES:
        raise ValueError(f"sender_sk_buf must be {SIGN_SECRETKEYBYTES} bytes")

    m = bytearray(ciphertext)
    m_addr = _sodium_ffi.from_buffer(m)
    sm = bytearray(len(ciphertext) + SIGN_BYTES)
    sm_addr = _sodium_ffi.from_buffer(sm)
    smlen_p = _sodium_ffi.new("unsigned long long *")

    rc = _sodium_lib.crypto_sign(sm_addr, smlen_p, m_addr, len(ciphertext), sender_sk_buf.addr)
    if rc != 0:
        raise RuntimeError(f"crypto_sign failed, rc={rc}")
    return bytes(sm[:smlen_p[0]])


def verify_and_unwrap(signed_ciphertext: bytes, sender_pk: bytes) -> bytes:
    """Verifies the Ed25519 signature over signed_ciphertext against
    sender_pk and returns the original ciphertext. Raises
    SignatureVerificationError on any failure -- forged signature, wrong
    sender key, or a payload swapped in from a different (even validly
    sealed) sender. Never returns unverified data."""
    if len(sender_pk) != SIGN_PUBLICKEYBYTES:
        raise ValueError(f"sender_pk must be {SIGN_PUBLICKEYBYTES} bytes")
    if len(signed_ciphertext) < SIGN_BYTES:
        raise ValueError("signed_ciphertext shorter than SIGN_BYTES -- not a valid signed block")

    sm = bytearray(signed_ciphertext)
    sm_addr = _sodium_ffi.from_buffer(sm)
    m = bytearray(len(signed_ciphertext))
    m_addr = _sodium_ffi.from_buffer(m)
    mlen_p = _sodium_ffi.new("unsigned long long *")
    pk = bytearray(sender_pk)
    pk_addr = _sodium_ffi.from_buffer(pk)

    rc = _sodium_lib.crypto_sign_open(m_addr, mlen_p, sm_addr, len(signed_ciphertext), pk_addr)
    if rc != 0:
        raise SignatureVerificationError(
            "crypto_sign_open failed -- forged signature, wrong sender identity "
            "key, or tampered/swapped payload. Refusing to trust output."
        )
    return bytes(m[:mlen_p[0]])
