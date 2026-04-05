import { useState } from "react";
import { api, eciesEncrypt, fromHex, signMessage, toHex } from "../api.js";

export default function Vote({ election, voter, onDone }) {
  const [choice, setChoice] = useState("");
  const [msg, setMsg] = useState(null);
  const [debug, setDebug] = useState(null);

  const canVote = voter && election?.phase === "open" && election?.candidates?.length;

  const handleVote = async () => {
    try {
      if (!choice) throw new Error("pick a candidate");

      // 1) sign the chosen candidate with the voter's Ed25519 private key
      const msgBytes = new TextEncoder().encode(choice);
      const signature = signMessage(fromHex(voter.privHex), msgBytes);

      // 2) encrypt the candidate to the authority's X25519 public key
      const authorityPub = fromHex(election.authority_pub);
      const ciphertext = await eciesEncrypt(authorityPub, msgBytes);

      // 3) submit
      const res = await api.vote({
        voter_id: voter.id,
        candidate: choice,
        signature_hex: toHex(signature),
        ciphertext_hex: toHex(ciphertext),
      });

      setMsg({ ok: true, text: `Ballot accepted (index ${res.index}).` });
      setDebug({
        signature_hex: toHex(signature),
        ciphertext_hex: toHex(ciphertext),
        hash: res.hash,
        prev_hash: res.prev_hash,
      });
      onDone?.();
    } catch (e) {
      setMsg({ ok: false, text: e.message });
    }
  };

  return (
    <div className="card">
      <h2>Cast Your Vote</h2>
      <p style={{ color: "var(--muted)", marginTop: 0 }}>
        Your choice is <strong>signed</strong> with your Ed25519 private
        key, then <strong>ECIES-encrypted</strong> to the election
        authority's public key before leaving the browser.
      </p>

      {!voter && <p className="err">Register first (step 1).</p>}
      {election?.phase !== "open" && (
        <p className="err">Election is not open.</p>
      )}

      <label>Candidate</label>
      <select value={choice} onChange={(e) => setChoice(e.target.value)}>
        <option value="">— select —</option>
        {election?.candidates?.map((c) => (
          <option key={c} value={c}>{c}</option>
        ))}
      </select>

      <div style={{ marginTop: 14 }}>
        <button onClick={handleVote} disabled={!canVote}>
          Sign, encrypt & submit
        </button>
      </div>

      {msg && <p className={msg.ok ? "ok" : "err"}>{msg.text}</p>}

      {debug && (
        <>
          <label>Signature (Ed25519, 64 bytes)</label>
          <pre>{debug.signature_hex}</pre>
          <label>Ciphertext (ECIES: ephPub ‖ nonce ‖ AES-GCM)</label>
          <pre>{debug.ciphertext_hex}</pre>
          <label>Hash-chain link</label>
          <pre>prev = {debug.prev_hash}{"\n"}this = {debug.hash}</pre>
        </>
      )}
    </div>
  );
}
