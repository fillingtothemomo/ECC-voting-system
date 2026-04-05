import { useEffect, useState } from "react";
import { api } from "./api.js";
import Register from "./components/Register.jsx";
import Vote from "./components/Vote.jsx";
import Results from "./components/Results.jsx";
import Admin from "./components/Admin.jsx";

const TABS = [
  { id: "register", label: "1. Register" },
  { id: "vote",     label: "2. Vote" },
  { id: "results",  label: "3. Results" },
  { id: "admin",    label: "Admin" },
];

export default function App() {
  const [tab, setTab] = useState("register");
  const [election, setElection] = useState(null);
  const [voter, setVoter] = useState(null);   // { id, privHex, pubHex }

  const refresh = async () => {
    try {
      setElection(await api.getElection());
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => { refresh(); }, []);

  return (
    <div className="container">
      <h1>ECC Voting System</h1>
      <div className="subtitle">
        BTP prototype &mdash; Ed25519 signatures + ECIES (X25519 / AES-GCM)
        + SHA-256 hash chain.
      </div>

      <div className="card">
        <div className="row" style={{ justifyContent: "space-between" }}>
          <div>
            <strong>{election?.title ?? "No election yet"}</strong>
            <div style={{ color: "var(--muted)", fontSize: 13 }}>
              phase: <code>{election?.phase ?? "none"}</code>
              {election?.num_registered != null && (
                <> &middot; registered: {election.num_registered} &middot; votes: {election.num_votes}</>
              )}
            </div>
          </div>
          <button onClick={refresh}>Refresh</button>
        </div>
      </div>

      <div className="tabs">
        {TABS.map((t) => (
          <button
            key={t.id}
            className={"tab" + (tab === t.id ? " active" : "")}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "register" && (
        <Register election={election} voter={voter} setVoter={setVoter} onDone={refresh} />
      )}
      {tab === "vote" && (
        <Vote election={election} voter={voter} onDone={refresh} />
      )}
      {tab === "results" && <Results election={election} />}
      {tab === "admin"   && <Admin   election={election} onChange={refresh} />}
    </div>
  );
}
