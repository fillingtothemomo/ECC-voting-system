"""
Flask REST API for the ECC voting prototype.

Endpoints (all JSON, all hex-encoded bytes):

    POST /api/election              create (admin)      body: {title, candidates:[..]}
    POST /api/election/open         open voting (admin)
    POST /api/election/close        close voting (admin)
    GET  /api/election              current snapshot + authority pubkey

    POST /api/register              body: {voter_id, pubkey_hex}
    POST /api/vote                  body: {voter_id, candidate, signature_hex, ciphertext_hex}

    GET  /api/ballots               full (encrypted) ballot box — for the report demos
    GET  /api/results               tally (only after close)

Run:
    python app.py
"""

from flask import Flask, jsonify, request
from flask_cors import CORS

from election import Election


app = Flask(__name__)
CORS(app)

# single global election for the prototype — auto-created at startup in
# the OPEN phase so the UI is immediately usable.
election: Election | None = Election(
    title="Department Election (default)",
    candidates=["Prof. Alice", "Prof. Bob", "Prof. Carol"],
)


def _need_election() -> Election:
    if election is None:
        raise ValueError("no election has been created yet")
    return election


# ---------- admin ---------------------------------------------------------

@app.post("/api/election")
def create_election():
    global election
    data = request.get_json(force=True)
    title = data.get("title", "Department Election")
    candidates = data.get("candidates") or []
    if not candidates:
        return jsonify(error="at least one candidate required"), 400
    election = Election(title=title, candidates=candidates)
    return jsonify(election.snapshot())


@app.post("/api/election/reopen")
def reopen_election():
    _need_election().reopen()
    return jsonify(_need_election().snapshot())


@app.post("/api/election/close")
def close_election():
    _need_election().close()
    return jsonify(_need_election().snapshot())


@app.get("/api/election")
def get_election():
    if election is None:
        return jsonify(phase="none"), 200
    return jsonify(election.snapshot())


# ---------- voter actions -------------------------------------------------

@app.post("/api/register")
def register():
    e = _need_election()
    data = request.get_json(force=True)
    voter_id = data["voter_id"]
    pubkey = bytes.fromhex(data["pubkey_hex"])
    e.register_voter(voter_id, pubkey)
    return jsonify(ok=True, voter_id=voter_id)


@app.post("/api/vote")
def vote():
    e = _need_election()
    data = request.get_json(force=True)
    result = e.cast_ballot(
        voter_id=data["voter_id"],
        candidate=data["candidate"],
        signature=bytes.fromhex(data["signature_hex"]),
        encrypted_blob=bytes.fromhex(data["ciphertext_hex"]),
    )
    return jsonify(ok=True, **result)


# ---------- read-only / admin inspection ----------------------------------

@app.get("/api/ballots")
def ballots():
    e = _need_election()
    return jsonify([
        {
            "index": b.index,
            "voter_id": b.voter_id,
            "ciphertext_hex": b.ciphertext.hex(),
            "prev_hash": b.prev_hash.hex(),
            "hash": b.hash.hex(),
        }
        for b in e.store.ballots
    ])


@app.get("/api/results")
def results():
    return jsonify(_need_election().tally())


# ---------- error handling ------------------------------------------------

@app.errorhandler(ValueError)
def on_value_error(err):
    return jsonify(error=str(err)), 400


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
