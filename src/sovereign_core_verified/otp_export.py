"""
otp_export.py -- sender-side export: local OTPPadStore -> chunked transport stream.

Mirrors otp_ingest.py's guarantees in the opposite direction: pad plaintext
flows locked-buffer -> locked-buffer (via OTPPadStore.reserve_into's
ffi.memmove, zero Python bytes/bytearray copy) -> sealed (crypto_box_seal,
pointer-only) -> signed (crypto_sign, pointer-only for the secret key) ->
chunked. The only bytes objects that ever exist are ciphertext/signed-
ciphertext/chunks -- none of which are secret, all of which are meant to
cross the transport boundary.

Atomicity: reserve_into() writes the journal BEFORE the memmove happens --
same invariant as otp_pad.py's reserve(). If the process crashes at any
point after this call returns, those pad bytes are burned locally and can
never be reissued, even though the transmission itself may never have
completed. This is a deliberate, correct one-time-pad property: "maybe
sent, definitely burned" is safe; "maybe sent, maybe reissued" is not.
"""
from sovereign_memory import SecureKeyBuffer
from otp_pad import OTPPadStore
from otp_transport import seal_pad, sign_and_wrap
from otp_chunking import encode_chunks


def export_pad_payload(pad_store: OTPPadStore, n: int, recipient_box_pk: bytes,
                        sender_sign_sk: SecureKeyBuffer, chunk_payload_size: int = 200,
                        session_id: bytes = None):
    """Atomically reserves n bytes from pad_store (burning them locally --
    see module docstring), seals them for recipient_box_pk, signs the
    result with sender_sign_sk, and returns a list of transport-ready
    chunks. Returns (source_offset, chunks) -- source_offset is metadata
    only, not a security-relevant value.

    Raises whatever pad_store.reserve_into() raises (OTPExhaustedError,
    RuntimeError if not finalized) BEFORE any sealing/signing/chunking is
    attempted -- if the reservation itself fails, nothing is sealed or
    transmitted, and (critically) nothing was burned either, since
    reserve_into() only advances the journal on its own successful path.
    """
    with SecureKeyBuffer(n) as plaintext_buf:
        # Atomic, zero-copy: journal advances BEFORE this call returns.
        # From this point on, these n pad bytes are burned locally
        # regardless of whether sealing/signing/chunking/transmission
        # below succeeds.
        source_offset = pad_store.reserve_into(n, plaintext_buf.addr)

        ciphertext = seal_pad(plaintext_buf, n, recipient_box_pk)
        # plaintext_buf.clear() happens automatically via the `with` block
        # exiting -- but note ciphertext (not secret) has already been
        # produced by this point, so clearing here doesn't lose anything.

    signed_ciphertext = sign_and_wrap(ciphertext, sender_sign_sk)
    chunks = list(encode_chunks(signed_ciphertext, chunk_payload_size=chunk_payload_size,
                                 session_id=session_id))
    return source_offset, chunks
