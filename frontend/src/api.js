// Thin wrapper around the Flask backend + client-side crypto helpers.
//
// Crypto done in the browser:
//   - Ed25519 key generation, signing           (@noble/curves/ed25519)
//   - ECIES: X25519 + HKDF-SHA256 + AES-256-GCM (@noble/curves + SubtleCrypto)
//
// Matches backend/crypto/encryption.py byte-for-byte so the authority can
// decrypt ballots cast from this UI.

import { ed25519, x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

const HKDF_INFO = new TextEncoder().encode("btp-ecc-voting/v1");

// ---------- hex helpers ---------------------------------------------------

export const toHex = (u8) =>
  Array.from(u8).map((b) => b.toString(16).padStart(2, "0")).join("");

export const fromHex = (hex) => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
};

// ---------- Ed25519 -------------------------------------------------------

export function generateVoterKeypair() {
  const priv = ed25519.utils.randomPrivateKey();       // 32 bytes
  const pub = ed25519.getPublicKey(priv);              // 32 bytes
  return { priv, pub };
}

export function signMessage(priv, messageBytes) {
  return ed25519.sign(messageBytes, priv);             // 64 bytes
}

// ---------- ECIES (encrypt-to-authority) ---------------------------------

export async function eciesEncrypt(authorityPub, plaintextBytes) {
  // Fresh ephemeral X25519 keypair
  const ephPriv = x25519.utils.randomPrivateKey();
  const ephPub = x25519.getPublicKey(ephPriv);

  // ECDH shared secret
  const shared = x25519.getSharedSecret(ephPriv, authorityPub);

  // HKDF-SHA256 -> 32 byte AES key (must match backend)
  const keyBytes = hkdf(sha256, shared, undefined, HKDF_INFO, 32);

  // AES-256-GCM via SubtleCrypto
  const key = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ctBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce }, key, plaintextBytes
  );

  // Layout:  ephPub(32) || nonce(12) || ciphertext+tag
  const ct = new Uint8Array(ctBuf);
  const out = new Uint8Array(32 + 12 + ct.length);
  out.set(ephPub, 0);
  out.set(nonce, 32);
  out.set(ct, 44);
  return out;
}

// ---------- REST wrappers ------------------------------------------------

async function jpost(path, body) {
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

async function jget(path) {
  const r = await fetch(path);
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

export const api = {
  getElection: () => jget("/api/election"),
  createElection: (title, candidates) =>
    jpost("/api/election", { title, candidates }),
  reopenElection: () => jpost("/api/election/reopen", {}),
  closeElection: () => jpost("/api/election/close", {}),
  register: (voter_id, pubkey_hex) =>
    jpost("/api/register", { voter_id, pubkey_hex }),
  vote: (payload) => jpost("/api/vote", payload),
  ballots: () => jget("/api/ballots"),
  results: () => jget("/api/results"),
};
