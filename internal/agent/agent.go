// Package agent is the signet agent — own-the-token, sign-on-request.
//
// signet is otherwise a one-shot CLI that opens the hardware on every call. That
// does not work when the workload that needs to attest cannot reach the hardware
// at all: a container has no pcscd socket and no path to the YubiKey, and mounting
// the token into the most exposed container is the wrong trade-off. The agent is
// the ssh-agent / SPIRE node-agent / HSM-proxy answer: one process owns the token
// and signs attestation nonces for socket clients on request.
//
// Two halves live here:
//
//   - the serve side (server.go, `signet agent --bind <socket>=<slot-or-identity>
//     ...`): one daemon owns the hardware and serves a Unix socket per binding.
//     Each socket is pinned to ONE key at listen time — a PIV slot under
//     --backend piv, a named identity under --backend tpm or secure-enclave —
//     and that key is never taken from a request, so a client on a socket can
//     only ever sign with that socket's key; it cannot impersonate another
//     identity. All hardware access is serialised through one mutex (needed for
//     a single-access token like a YubiKey; harmless overhead for TPM/Enclave).
//     The agent exposes exactly two ops, pubkey and sign; it never generates or
//     overwrites a key (enrolment stays a deliberate host operation).
//
//   - the client side (client.go, selected by `--agent <socket>` on sign / enrol
//     / auth / verify): a Signer that forwards PublicKeyDER and Sign over the
//     socket instead of opening local hardware. Because attestation is
//     resolve-by-public-key, the broker neither knows nor cares that the
//     signature came via the agent.
//
// Security model: the private key never leaves the hardware and the hardware
// never leaves the agent. A compromised client can ask for a signature over a
// nonce, but the broker's challenge nonces are single-use (replay-dead) and the
// socket's fixed key binding stops it attesting as anything but itself; it
// cannot extract a key.
package agent

import "time"

// connTimeout bounds a single request/response exchange on the serve side;
// dialTimeout bounds the client's dial-plus-exchange. Both are generous
// enough for a YubiKey touch-free signature, which is sub-second.
const (
	connTimeout = 15 * time.Second
	dialTimeout = 15 * time.Second
	socketMode  = 0o660
)

// request and response are the newline-delimited JSON wire protocol.
// A request names an op (and, for sign, the message); the slot is NEVER carried
// on the wire — it is fixed by the socket the client connected to.
type request struct {
	Op      string `json:"op"`                // "pubkey" | "sign"
	Message string `json:"message,omitempty"` // sign only
}

type response struct {
	PublicKeyDER string `json:"public_key_der,omitempty"`
	SignatureB64 string `json:"signature_b64,omitempty"`
	Error        string `json:"error,omitempty"`
}
