"""
SHA-256 hash chain for the ballot box.

Each stored ballot keeps a field `prev_hash` that points at the hash of
the previous entry. Changing any earlier ballot would invalidate every
hash that follows, so the box is tamper-evident *without* needing a
blockchain.

    entry_hash(i) = SHA256( prev_hash(i)  ||  ballot_bytes(i) )

The genesis entry uses prev_hash = 32 zero bytes.
"""

import hashlib


GENESIS = b"\x00" * 32


def chain_hash(prev_hash: bytes, payload: bytes) -> bytes:
    return hashlib.sha256(prev_hash + payload).digest()


def verify_chain(entries: list[dict]) -> bool:
    """
    Each entry is a dict with keys:
        "prev_hash": hex str
        "hash"     : hex str
        "payload"  : bytes-like (e.g. the raw encrypted ballot)
    Returns True iff every link is intact and starts from GENESIS.
    """
    expected_prev = GENESIS
    for e in entries:
        if bytes.fromhex(e["prev_hash"]) != expected_prev:
            return False
        h = chain_hash(expected_prev, e["payload"])
        if bytes.fromhex(e["hash"]) != h:
            return False
        expected_prev = h
    return True
