import { useState } from "react";
import { api } from "../api.js";

export default function Results({ election }) {
  const [tally, setTally] = useState(null);
  const [ballots, setBallots] = useState(null);
  const [err, setErr] = useState(null);

  const loadResults = async () => {
    try {
      setErr(null);
      setTally(await api.results());
    } catch (e) { setErr(e.message); }
  };

  const loadBallots = async () => {
    try {
      setErr(null);
      setBallots(await api.ballots());
    } catch (e) { setErr(e.message); }
  };

  return (
    <div className="card">
      <h2>Results</h2>
      <p style={{ color: "var(--muted)", marginTop: 0 }}>
        After the election is <code>closed</code>, the authority decrypts
        each stored ballot with its X25519 private key and tallies the
        candidates.
      </p>

      <div style={{ display: "flex", gap: 8 }}>
        <button onClick={loadResults} disabled={election?.phase !== "closed"}>
          Load tally
        </button>
        <button onClick={loadBallots}>Show encrypted ballot box</button>
      </div>

      {err && <p className="err">{err}</p>}

      {tally && (
        <>
          <h3>Final tally</h3>
          <pre>{Object.entries(tally).map(([c, n]) => `${c}:  ${n}`).join("\n")}</pre>
        </>
      )}

      {ballots && (
        <>
          <h3>Ballot box ({ballots.length})</h3>
          {ballots.map((b) => (
            <pre key={b.index}>
{`#${b.index}  voter=${b.voter_id}
prev = ${b.prev_hash}
hash = ${b.hash}
ct   = ${b.ciphertext_hex.slice(0, 96)}...`}
            </pre>
          ))}
        </>
      )}
    </div>
  );
}
