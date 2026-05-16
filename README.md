# Code for B.S. Project on *A Comparative Study of ECC and Post-Quantum Lattice Cryptography in Electronic Voting Systems*

> **Author:** Angel Sharma  ·  **Programme:** B.S (Mathematics and Computing)
> **Repository status:** dissertation prototype — research code, not production software.

📄 **[Project presentation (PDF)](report_presentation.pdf)** — slide deck accompanying the dissertation.

This repository contains the full implementation, benchmarking harness and
front-end demo built for the dissertation. The project compares **classical
Elliptic-Curve Cryptography (ECC)** against **post-quantum lattice
cryptography** (Regev's LWE scheme, with an ML-KEM reference) inside a single,
end-to-end electronic-voting prototype so that both schemes can be measured
on identical workloads.

The same Flask + React application runs in either mode at the flip of a
switch, which lets the dissertation make a *like-for-like* argument about
correctness, performance and the structural differences in how each scheme
handles the tally.

---

## 1. Aims of the study

1. Build a working e-voting flow that exercises every cryptographic
   primitive a real election would need — voter authentication, ballot
   confidentiality, integrity, and verifiability.
2. Implement that flow **twice** — once with ECC, once with lattice
   cryptography — sharing as much surrounding code as possible.
3. Measure the cost of each scheme end-to-end (key generation, per-ballot
   encryption, total cast, tally) and identify the qualitative differences
   that pure timings hide (e.g. homomorphic tallying).
4. Provide a teaching artefact: a pure-Python ECC module that students
   can step through to see point arithmetic and ElGamal-on-a-curve at
   work.

---

## 2. What is implemented

| Concern                       | ECC mode                                            | Lattice mode                                                   |
|-------------------------------|-----------------------------------------------------|----------------------------------------------------------------|
| Voter identity / signing      | Ed25519 (EdDSA)                                     | Ed25519 (EdDSA) — signature scheme is shared                   |
| Ballot confidentiality        | ECIES — X25519 ECDH + HKDF-SHA256 + AES-256-GCM     | Regev LWE public-key encryption (one-hot encoded ballot)       |
| Tally method                  | Decrypt every ballot individually                   | **Homomorphic** sum of ciphertexts; decrypt only the totals    |
| Ballot-box integrity          | SHA-256 hash chain (shared)                         | SHA-256 hash chain (shared)                                    |
| Post-quantum reference KEM    | —                                                   | ML-KEM-512 / 768 / 1024 (FIPS 203) via `kyber-py`              |
| Teaching module               | Pure-Python ECC over a small prime field + ElGamal  | Regev parameters TOY and STANDARD with explanatory dataclasses |

The lattice mode exploits the additive homomorphism of Regev encryption:
each ballot is a one-hot vector of ciphertexts (one per candidate), the
server sums the ciphertexts component-wise, and the authority decrypts
only the *N* per-candidate totals — not the *N × voters* individual
ballots. This is the central structural advantage the dissertation
quantifies.

---

## 3. End-to-end flow

```
┌──────────┐  Ed25519 keypair        ┌──────────┐
│  Voter   │ ──────────────────────► │ Server   │
│ (browser)│  register pubkey        │ (Flask)  │
└──────────┘                         └──────────┘
     │                                    ▲
     │ sign(candidate)                    │
     │ encrypt(candidate, authority_pk)   │
     ▼                                    │
   ballot ──── POST /api/vote ────────────┘
                                       │
                                       │  verify signature
                                       │  reject duplicates
                                       │  append → SHA-256 hash chain
                                       ▼
                                  ballot box
                                       │
                                       │  /api/election/close
                                       ▼
                       ECC mode:   decrypt each ballot, count
                       Lattice:    homomorphic sum, decrypt N totals
```

---

## 4. Project layout

```
ECC-voting-system/
├── backend/                       # Python (Flask) API + cryptography
│   ├── app.py                     # REST endpoints
│   ├── election.py                # Election state machine (ECC + Lattice)
│   ├── storage.py                 # In-memory store + hash-chained ballot box
│   ├── benchmark.py               # Side-by-side ECC vs Lattice timing harness
│   ├── requirements.txt
│   └── crypto/
│       ├── ecc_math.py            # Pure-Python ECC over a small prime (teaching)
│       ├── signatures.py          # Ed25519 sign / verify (cryptography lib)
│       ├── encryption.py          # ECIES: X25519 + HKDF-SHA256 + AES-256-GCM
│       ├── hashing.py             # SHA-256 hash-chain helpers
│       └── lattice/
│           ├── regev.py           # Regev LWE keygen / encrypt / decrypt / add
│           └── mlkem.py           # ML-KEM-512/768/1024 wrapper (FIPS 203)
│
└── frontend/                      # React (Vite) voter UI — "Cryptavote"
    ├── index.html
    ├── package.json
    ├── vite.config.js
    └── src/
        ├── main.jsx
        ├── App.jsx                # Dashboard + mode badge + nav
        ├── api.js                 # fetch wrapper around the Flask API
        └── components/
            ├── Register.jsx       # Ed25519 keypair generated in-browser
            ├── Vote.jsx           # Sign + encrypt + submit
            ├── Results.jsx        # Tally after election closes
            └── Admin.jsx          # Mode switch, open/close election
```

---

## 5. Running the prototype

### 5.1 Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# Lattice mode additionally requires `kyber-py` for ML-KEM:
pip install kyber-py
python app.py                       # serves on http://localhost:5000
```

### 5.2 Frontend

```bash
cd frontend
npm install
npm run dev                         # http://localhost:5173
```

### 5.3 Using the demo

1. Open the frontend in a browser.
2. *Admin* tab → choose **ECC** or **Lattice** mode (this resets the
   election); optionally set the title and candidate list.
3. *Register* tab → generates an Ed25519 keypair in the browser; the
   public key is sent to the server.
4. *Cast Vote* tab → the chosen candidate is signed in the browser; in
   ECC mode it is also encrypted in the browser with ECIES against the
   authority's X25519 public key; in lattice mode the server-side
   election object performs the Regev one-hot encryption.
5. *Admin* tab → close the election.
6. *Results* tab → shows the tally and the hash-chain integrity flag.

---

## 6. Benchmark — the experimental core of the dissertation

`backend/benchmark.py` runs the same set of ballots through both modes
and prints a comparison table.

```bash
cd backend
source .venv/bin/activate
python benchmark.py
```

It reports, per mode:

* authority key-generation time,
* mean Ed25519 sign time,
* mean per-ballot encryption time,
* total time to cast all ballots,
* total tally time,
* and verifies that **both modes recover the same ground-truth tally**.

The interesting result is in the tally row: ECC decrypts every ballot
individually (cost ∝ number of voters), while the lattice mode sums
ciphertexts homomorphically and decrypts only one ciphertext per
candidate. The crossover point and constants are exactly what the
dissertation discusses.

Tune `N_VOTERS`, `CANDIDATES` and `SEED` at the top of the file to
re-run under different loads.

---

## 7. Teaching module — pure-Python ECC

`backend/crypto/ecc_math.py` is a self-contained, textbook
implementation of elliptic-curve arithmetic over a small prime field
(`y² = x³ + 2x + 2 mod 17`). It implements point addition, doubling,
scalar multiplication and an ElGamal encrypt/decrypt demo with values
small enough to follow on paper. Run it directly:

```bash
python backend/crypto/ecc_math.py
```

This module is referenced in the dissertation chapter that introduces
the mathematics underlying Curve25519.

---

## 8. Lattice background

* `crypto/lattice/regev.py` — Regev's 2005 LWE public-key encryption.
  Two parameter sets are supplied:
  * `TOY` (n=16, m=64, q=2053) — small enough to inspect by hand.
  * `STANDARD` (n=256, m=512, q=1048583) — used by the application and
    benchmark; comfortable noise budget at the chosen plaintext bound.
  Provides `keygen`, `encrypt`, `decrypt`, `add_ciphertexts`, and a
  convenience `tally`.

* `crypto/lattice/mlkem.py` — wrapper around the pure-Python
  [`kyber-py`](https://pypi.org/project/kyber-py/) implementation of
  ML-KEM (FIPS 203), included as a reference for current
  NIST-standardised post-quantum key encapsulation. Not on the
  voting hot path; provided for the comparison chapter.

---

## 9. Threat model and known weaknesses (research scope)

This is a dissertation prototype intended to make the cryptography
visible, not a deployable election system. The following are
intentionally simple and are discussed as part of the analysis:

* In-memory storage only; no persistence between restarts.
* The voter list is open — anyone can register a public key; a real
  deployment would gate this with institutional identity.
* The ECIES ephemeral key is fresh per ballot (correct), but the code
  highlights what happens if a deployer were to reuse it.
* Submission order is observable, which leaks an upper bound on the
  voter→ballot mapping; mitigations (mixnets, batching) are discussed
  in the dissertation but not implemented.
* No cover-traffic, no zero-knowledge proof that a lattice ballot is
  actually a valid one-hot vector — a malicious voter encrypting `255`
  for their candidate would still tally. The dissertation discusses
  range proofs / NIZKs as the natural next step.
* `kyber-py` is a pure-Python ML-KEM and is **not constant-time**; it
  is included for functional comparison only.

---

## 10. Reproducibility checklist

* Python 3.10+ (uses `X | Y` union syntax and `match`).
* Node 18+ for the frontend.
* `pip install -r backend/requirements.txt` then `pip install kyber-py`.
* `npm install` inside `frontend/`.
* `python backend/benchmark.py` reproduces the headline numbers.
* `python backend/crypto/ecc_math.py` reproduces the teaching demo.

---

## 11. License

Released for academic use as part of the author's B.Tech dissertation.
No warranty; not for use in real elections.
