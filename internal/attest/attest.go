// Package attest speaks the broker /v1/attest HTTP contract: request a
// challenge, sign it in hardware, exchange the proof for a short-lived bearer,
// and renew that bearer as it ages. It also carries the two CLI flows built on
// that contract: Auth (the credential helper) and Verify (the consumer
// pre-flight).
//
// The broker is a black box reached over the wire; this package vendors no
// broker code and makes no authorisation decision (.claude/rules/15-attest-boundary.md).
package attest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/radar-hooves/signet/internal/signer"
)

// tokenResult is the broker's response to /v1/attest/token and /v1/attest/renew.
type tokenResult struct {
	Key          string `json:"key"`
	KeyID        string `json:"key_id"`
	Name         string `json:"name"`
	ExpiresAt    string `json:"expires_at"`
	MaxExpiresAt string `json:"max_expires_at"`
}

// challengeResult is the broker's response to /v1/attest/challenge.
type challengeResult struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
	ExpiresAt   string `json:"expires_at"`
}

// BrokerError is a non-2xx HTTP response from the broker. It carries the
// status so callers can classify a rejection (401 on renew → re-attest;
// any 4xx during verify → attestation rejected) without parsing message text.
type BrokerError struct {
	Status int
	Body   string
}

func (e *BrokerError) Error() string {
	return fmt.Sprintf("broker %d: %s", e.Status, e.Body)
}

// attestRejectedHint is the ONE guidance line every consumer subcommand
// (verify, headers, vend-to-file, exec) prints after a broker-rejected
// attestation. A 4xx there means the broker ANSWERED — the refusal is local
// — but the raw error ("broker 401: ...") reads exactly like a broker fault,
// and the reader gets sent off diagnosing the wrong system: the usual cause
// is the default identity's key simply not being enrolled with this broker.
// verify alone carried this wording until 2026-09-02 while headers,
// vend-to-file and exec — the paths a real consumer actually takes, headers
// above all, as every headersHelper runs it — printed the bare 401; four
// hand-maintained copies would drift the same way, hence one shared line.
func attestRejectedHint() string {
	return "local, not an outage: this key is not enrolled for the identity in use — " +
		"--identity selects the secure-enclave or tpm key, --slot the PIV slot; unset uses the default"
}

// canonicalMessage constructs the UTF-8 message the broker's canonical form
// prescribes: "{challenge_id}.{nonce}".
// This is the string that must be SHA-256 digested and signed.
func canonicalMessage(challengeID, nonce string) string {
	return challengeID + "." + nonce
}

// brokerPost sends a POST request with a JSON body to endpoint and decodes the
// JSON response into result. If bearerKey is non-empty, it is sent as an
// Authorization: Bearer header. A non-2xx response returns a *BrokerError.
func brokerPost(endpoint string, body any, bearerKey string, result any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearerKey != "" {
		req.Header.Set("Authorization", "Bearer "+bearerKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &BrokerError{Status: resp.StatusCode, Body: strings.TrimSpace(string(respBody))}
	}
	if err := json.Unmarshal(respBody, result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// attestFresh performs legs 1 and 2 of the attestation protocol:
// /v1/attest/challenge then /v1/attest/token.
//
// The broker resolves the identity from the presented public key
// (resolve-by-key). Leg 1 sends {"public_key_der": <spki-b64>}; leg 2 sends only
// {challenge_id, nonce, signature_b64} — identity_id is not sent.
func attestFresh(s signer.Signer, brokerURL string) (*bearerCache, error) {
	// Obtain the enrolled public key; fail fast if no key has been enrolled.
	spkiB64, err := s.PublicKeyDER()
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}

	// Leg 1: request a challenge, presenting the public key.
	var cr challengeResult
	if err := brokerPost(brokerURL+"/v1/attest/challenge", map[string]string{"public_key_der": spkiB64}, "", &cr); err != nil {
		return nil, fmt.Errorf("attest/challenge: %w", err)
	}

	// Sign the canonical message via the backend-agnostic Signer interface.
	msg := canonicalMessage(cr.ChallengeID, cr.Nonce)
	sigB64, err := s.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("sign challenge: %w", err)
	}

	// Leg 2: exchange the signature for a bearer. identity_id is NOT sent —
	// the broker resolves the identity from the public key stored at leg 1.
	tokenBody := map[string]string{
		"challenge_id":  cr.ChallengeID,
		"nonce":         cr.Nonce,
		"signature_b64": sigB64,
	}
	var tr tokenResult
	if err := brokerPost(brokerURL+"/v1/attest/token", tokenBody, "", &tr); err != nil {
		return nil, fmt.Errorf("attest/token: %w", err)
	}
	return bearerCacheFromToken(tr)
}

// renewBearer attempts leg 3: POST /v1/attest/renew with the current bearer.
// Returns nil, nil when the broker returns 401 (max lifetime exceeded; caller
// should fall through to attestFresh).
func renewBearer(brokerURL, currentKey string) (*bearerCache, error) {
	var tr tokenResult
	err := brokerPost(brokerURL+"/v1/attest/renew", map[string]string{}, currentKey, &tr)
	if err != nil {
		var be *BrokerError
		if errors.As(err, &be) && be.Status == http.StatusUnauthorized {
			return nil, nil // max lifetime exceeded; re-attest
		}
		return nil, fmt.Errorf("attest/renew: %w", err)
	}
	return bearerCacheFromToken(tr)
}
