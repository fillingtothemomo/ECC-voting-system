import { useState } from "react";
import { api } from "../api.js";

export default function Admin({ election, onChange }) {
  const [title, setTitle] = useState("HOD Election 2026");
  const [candidates, setCandidates] = useState("Prof. Alice, Prof. Bob, Prof. Carol");
  const [err, setErr] = useState(null);

  const run = async (fn) => {
    try {
      setErr(null);
      await fn();
      onChange?.();
    } catch (e) { setErr(e.message); }
  };

  return (
    <div className="card">
      <h2>Election Admin</h2>
      <p style={{ color: "var(--muted)", marginTop: 0 }}>
        A default election is created (already <code>open</code>) when
        the server starts. Create replaces it with a new one — also
        immediately open. Close freezes voting so the tally can be
        computed; Reopen undoes a close.
      </p>

      <label>Title</label>
      <input value={title} onChange={(e) => setTitle(e.target.value)} />

      <label>Candidates (comma-separated)</label>
      <input value={candidates} onChange={(e) => setCandidates(e.target.value)} />

      <div style={{ marginTop: 14, display: "flex", gap: 8, flexWrap: "wrap" }}>
        <button
          onClick={() => run(() =>
            api.createElection(title, candidates.split(",").map((s) => s.trim()).filter(Boolean))
          )}
        >
          Create
        </button>
        <button onClick={() => run(api.closeElection)}  disabled={election?.phase !== "open"}>Close</button>
        <button onClick={() => run(api.reopenElection)} disabled={election?.phase !== "closed"}>Reopen</button>
      </div>

      {err && <p className="err">{err}</p>}

      {election?.authority_pub && (
        <>
          <label>Authority X25519 public key (used for ECIES encryption)</label>
          <pre>{election.authority_pub}</pre>
        </>
      )}
    </div>
  );
}
