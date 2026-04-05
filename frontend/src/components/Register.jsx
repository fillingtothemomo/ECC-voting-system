import { useState } from "react";
import { api, generateVoterKeypair, toHex } from "../api.js";

export default function Register({ election, voter, setVoter, onDone }) {
  const [voterId, setVoterId] = useState("");
  const [msg, setMsg] = useState(null);

  const handleGenerate = () => {
    const { priv, pub } = generateVoterKeypair();
    setVoter({
      id: voterId || `voter_${Math.random().toString(36).slice(2, 8)}`,
      privHex: toHex(priv),
      pubHex: toHex(pub),
    });
    setMsg({ ok: true, text: "Keypair generated in the browser." });
  };

  const handleRegister = async () => {
    try {
      await api.register(voter.id, voter.pubHex);
      setMsg({ ok: true, text: `Registered as ${voter.id}.` });
      onDone?.();
    } catch (e) {
      setMsg({ ok: false, text: e.message });
    }
  };

  return (
    <div className="card">
      <h2>Voter Registration</h2>
      <p style={{ color: "var(--muted)", marginTop: 0 }}>
        Step 1 in the protocol. Your Ed25519 keypair is generated locally
        in this browser &mdash; the private key never leaves your machine.
        Only the public key is sent to the election server.
      </p>

      <label>Voter ID (any unique handle)</label>
      <input
        value={voterId}
        onChange={(e) => setVoterId(e.target.value)}
        placeholder="e.g. cs21b001"
      />

      <div style={{ marginTop: 14, display: "flex", gap: 8 }}>
        <button onClick={handleGenerate}>Generate Ed25519 keypair</button>
        <button
          onClick={handleRegister}
          disabled={!voter || election?.phase !== "open"}
        >
          Submit public key to server
        </button>
      </div>

      {election?.phase !== "open" && (
        <p className="err" style={{ fontSize: 13 }}>
          Election must be in <code>open</code> phase to register.
        </p>
      )}

      {voter && (
        <>
          <label>Your public key (sent to server)</label>
          <pre>{voter.pubHex}</pre>
          <label>Your private key (kept only in this tab — save it!)</label>
          <pre>{voter.privHex}</pre>
        </>
      )}

      {msg && <p className={msg.ok ? "ok" : "err"}>{msg.text}</p>}
    </div>
  );
}
