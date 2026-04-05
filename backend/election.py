"""
Election state machine.

Phases:
    OPEN    -> voters may register and cast ballots  (the default)
    CLOSED  -> no more votes; authority may decrypt & tally

An election is created directly in the OPEN phase so the prototype is
immediately usable — no separate "setup" step. The authority keypair
(X25519) is generated at construction time. In a real deployment the
private key would live in an HSM or be split via threshold decryption
(see "Future Scope" in the report).
"""

from enum import Enum

from crypto import encryption, signatures
from storage import Store


class Phase(str, Enum):
    OPEN = "open"
    CLOSED = "closed"


class Election:
    def __init__(self, title: str, candidates: list[str]):
        self.title = title
        self.candidates = list(candidates)
        self.phase = Phase.OPEN          # always start open
        self.store = Store()

        # authority X25519 keypair (for ECIES decryption of ballots)
        self.authority_priv, self.authority_pub = encryption.generate_authority_keypair()

        self._tally: dict[str, int] | None = None

    # ---- lifecycle ---------------------------------------------
    def reopen(self) -> None:
        """Re-open a closed election (prototype convenience)."""
        self.phase = Phase.OPEN
        self._tally = None

    def close(self) -> None:
        if self.phase != Phase.OPEN:
            raise ValueError(f"cannot close from phase {self.phase}")
        self.phase = Phase.CLOSED

    # ---- voter actions -----------------------------------------
    def register_voter(self, voter_id: str, pubkey: bytes) -> None:
        if self.phase != Phase.OPEN:
            raise ValueError("registration only allowed while election is open")
        self.store.register_voter(voter_id, pubkey)

    def cast_ballot(self, voter_id: str, candidate: str,
                    signature: bytes, encrypted_blob: bytes) -> dict:
        """
        Verify + store a ballot.

        The `encrypted_blob` is an ECIES ciphertext of the plaintext
        `candidate` string (produced by the client). We also require a
        separate Ed25519 signature over the candidate so the server can
        check *authenticity* before decryption time.

        NOTE for the vulnerability analysis: because we verify the
        signature against the *plaintext* candidate, the client has to
        send it alongside the ciphertext here. In a stronger protocol
        the candidate would stay encrypted end-to-end and a zero-
        knowledge proof would show the ciphertext encodes a valid
        option — see the Future Scope section.
        """
        if self.phase != Phase.OPEN:
            raise ValueError("election is not open")
        if candidate not in self.candidates:
            raise ValueError("unknown candidate")

        pub = self.store.get_voter_pubkey(voter_id)
        if pub is None:
            raise ValueError("voter is not registered")

        if voter_id in self.store.voted:
            raise ValueError("voter has already voted")

        if not signatures.verify(pub, candidate.encode("utf-8"), signature):
            raise ValueError("invalid signature — ballot rejected")

        ballot = self.store.append_ballot(voter_id, encrypted_blob)
        return {
            "index": ballot.index,
            "hash": ballot.hash.hex(),
            "prev_hash": ballot.prev_hash.hex(),
        }

    # ---- tally -------------------------------------------------
    def tally(self) -> dict[str, int]:
        if self.phase != Phase.CLOSED:
            raise ValueError("election is not closed yet")
        if self._tally is not None:
            return self._tally

        counts = {c: 0 for c in self.candidates}
        for b in self.store.ballots:
            plaintext = encryption.decrypt(self.authority_priv, b.ciphertext)
            candidate = plaintext.decode("utf-8")
            if candidate in counts:
                counts[candidate] += 1
        self._tally = counts
        return counts

    # ---- introspection -----------------------------------------
    def snapshot(self) -> dict:
        return {
            "title": self.title,
            "phase": self.phase.value,
            "candidates": self.candidates,
            "authority_pub": self.authority_pub.hex(),
            "num_registered": len(self.store.voters),
            "num_votes": len(self.store.ballots),
            "chain_ok": self.store.chain_ok(),
        }
