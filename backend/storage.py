"""
In-memory store for the prototype.

Holds:
    - registered voters  (voter_id -> Ed25519 public key)
    - ballot box         (hash-chained list of encrypted ballots)
    - set of voter_ids that have already voted (to stop duplicates)

A real deployment would back this with a database; keeping it in memory
makes the crypto flow easy to follow in the BTP report.
"""

from dataclasses import dataclass, field
from typing import Optional

from crypto.hashing import GENESIS, chain_hash


@dataclass
class Ballot:
    index: int
    voter_id: str                    # so we can verify signatures later
    ciphertext: bytes                # ECIES-encrypted (signature + vote)
    prev_hash: bytes
    hash: bytes


@dataclass
class Store:
    voters: dict[str, bytes] = field(default_factory=dict)        # id -> ed25519 pub
    voted:  set[str]          = field(default_factory=set)
    ballots: list[Ballot]     = field(default_factory=list)

    # ---- voters ------------------------------------------------
    def register_voter(self, voter_id: str, pubkey: bytes) -> None:
        if voter_id in self.voters:
            raise ValueError("voter already registered")
        self.voters[voter_id] = pubkey

    def get_voter_pubkey(self, voter_id: str) -> Optional[bytes]:
        return self.voters.get(voter_id)

    # ---- ballot box --------------------------------------------
    def append_ballot(self, voter_id: str, ciphertext: bytes) -> Ballot:
        if voter_id in self.voted:
            raise ValueError("voter has already voted")

        prev = self.ballots[-1].hash if self.ballots else GENESIS
        h = chain_hash(prev, ciphertext)
        ballot = Ballot(
            index=len(self.ballots),
            voter_id=voter_id,
            ciphertext=ciphertext,
            prev_hash=prev,
            hash=h,
        )
        self.ballots.append(ballot)
        self.voted.add(voter_id)
        return ballot

    def chain_ok(self) -> bool:
        prev = GENESIS
        for b in self.ballots:
            if b.prev_hash != prev:
                return False
            if b.hash != chain_hash(prev, b.ciphertext):
                return False
            prev = b.hash
        return True
