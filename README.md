# ECC-Based Secure Department Voting System

A proof-of-concept BTP project demonstrating Elliptic Curve Cryptography
(ECC) applied to a small-scale department election (HOD / DAPC).

The focus is the **math behind ECC**; the web app is a thin shell to show
how the cryptographic primitives fit together in a realistic flow.

## What it demonstrates

| Primitive            | Used for                                  | Library / file            |
|----------------------|-------------------------------------------|---------------------------|
| ECC over finite field| Teaching / point add + scalar multiply    | `backend/crypto/ecc_math.py` |
| Ed25519 (EdDSA)      | Voter signature (authenticity)            | `backend/crypto/signatures.py` |
| X25519 + HKDF + AES-GCM (ECIES) | Vote encryption (confidentiality) | `backend/crypto/encryption.py` |
| SHA-256 hash chain   | Tamper-evident ballot box                 | `backend/crypto/hashing.py` |

## Flow

1. **Registration** — Voter generates an Ed25519 keypair in the browser.
   The public key is registered with the server (the "digital ID").
2. **Voting**
   - Voter signs the chosen candidate with their Ed25519 private key.
   - The signed ballot is encrypted to the election-authority's X25519
     public key using ECIES.
   - Server verifies the signature, rejects duplicates, appends the
     encrypted ballot to a SHA-256 hash chain.
3. **Tallying** — The election authority decrypts each ballot with its
   private key and computes the tally.

## Project layout

```
btp/
├── backend/                  # Python (Flask) API + crypto
│   ├── app.py                # REST endpoints
│   ├── election.py           # Election state machine
│   ├── storage.py            # In-memory store + hash chain
│   ├── requirements.txt
│   └── crypto/
│       ├── ecc_math.py       # Pure-Python ECC over a small prime (teaching)
│       ├── signatures.py     # Ed25519 sign / verify
│       ├── encryption.py     # ECIES (X25519 + HKDF + AES-GCM)
│       └── hashing.py        # SHA-256 hash-chain helper
│
└── frontend/                 # React (Vite) voter UI
    ├── index.html
    ├── package.json
    ├── vite.config.js
    └── src/
        ├── main.jsx
        ├── App.jsx
        ├── api.js
        └── components/
            ├── Register.jsx
            ├── Vote.jsx
            ├── Results.jsx
            └── Admin.jsx
```

## Running

### Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py           # http://localhost:5000
```

### Frontend

```bash
cd frontend
npm install
npm run dev             # http://localhost:5173
```

Open the frontend, register as a voter, cast a vote, then open the Admin
tab to close the election and view the tally.

## Learning module (standalone)

`backend/crypto/ecc_math.py` is a self-contained, pure-Python
implementation of ECC over a small prime field. Run it directly to see
point addition, doubling, scalar multiplication, and an ElGamal
encrypt/decrypt demo:

```bash
python backend/crypto/ecc_math.py
```

## Vulnerability notes (for the report)

The code includes comments pointing out where the system would become
insecure:
- reusing the ECIES ephemeral key (weak randomness)
- stripping the signature before storage
- allowing replay of the same encrypted ballot
- leaking voter→ballot mapping via submission order

These are discussed in the project report and demonstrated through
small experiments on the stored data.
