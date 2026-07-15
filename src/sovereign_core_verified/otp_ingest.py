"""
otp_ingest.py -- ingestion bridge.

Connects a completed ChunkReassembler through Ed25519 signature
verification and sealed-box decryption directly into a freshly constructed
OTPPadStore's own locked buffer. No plaintext pad material -- and no
intermediate signed/sealed blob -- ever touches a persistent, unauthenticated
temporary file, and no journal is ever created for a pad store whose
material hasn't been fully verified and decrypted.

Fail-shut points, in order:
  1. Reassembly incomplete (sequence/session violations already caught by
     ChunkReassembler.ingest() at chunk-arrival time; this is a final
     completeness check before trusting assemble()).
  2. Ed25519 signature over the reassembled block doesn't verify.
  3. Sealed-box decryption/authentication fails (wrong keypair, tampered
     ciphertext).
  4. Decrypted plaintext length doesn't exactly match the expected pad_size.

On ANY of these, the allocated locked buffer is cleared and no journal
file is written -- OTPPadStore.finalize_fill() is only reached after every
prior check has succeeded.
"""
from otp_chunking import ChunkReassembler, ChunkFormatError
from otp_transport import verify_and_unwrap, open_sealed, SignatureVerificationError, SealFailedError
from otp_pad import OTPPadStore


class IngestionAbortedError(Exception):
    """Raised when any stage of the ingestion pipeline fails. No journal
    file is created and no locked buffer is left allocated when this is
    raised -- cleanup has already happened before it propagates."""
    pass


def ingest_assembled_payload(reassembler: ChunkReassembler, sender_verify_pk: bytes,
                              recipient_box_pk, recipient_box_sk,
                              pad_size: int, journal_path: str) -> OTPPadStore:
    """Returns a fully finalized, usable OTPPadStore on success. Raises
    IngestionAbortedError on any failure, with the store's locked buffer
    already cleared and no journal file written."""

    if reassembler.total_chunks is None or reassembler.next_expected_seq != reassembler.total_chunks:
        raise IngestionAbortedError(
            "reassembly incomplete -- refusing to initialize pad store "
            f"(received {reassembler.next_expected_seq} of {reassembler.total_chunks!r})"
        )

    try:
        signed_ciphertext = reassembler.assemble()
    except ChunkFormatError as e:
        raise IngestionAbortedError(f"reassembly failed at assemble(): {e}") from e

    try:
        ciphertext = verify_and_unwrap(signed_ciphertext, sender_verify_pk)
    except SignatureVerificationError as e:
        raise IngestionAbortedError(
            f"signature verification failed -- refusing to initialize pad store: {e}"
        ) from e

    store = OTPPadStore(pad_size=pad_size, journal_path=journal_path, defer_fill=True)
    try:
        n = open_sealed(ciphertext, recipient_box_pk, recipient_box_sk, store)
        if n != pad_size:
            raise IngestionAbortedError(
                f"decrypted plaintext length {n} does not match expected pad_size {pad_size}"
            )
        store.finalize_fill()
    except (SealFailedError, IngestionAbortedError, ValueError) as e:
        store.clear()
        if isinstance(e, IngestionAbortedError):
            raise
        raise IngestionAbortedError(f"sealed-box decryption failed: {e}") from e
    except Exception:
        store.clear()
        raise

    return store
