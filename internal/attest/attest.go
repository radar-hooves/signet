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
	"os"
	"strconv"
	"strings"
	"time"

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
// and the reader gets sent off diagnosing the wrong system.
//
// It used to name one cause with confidence ("this key is not enrolled").
// That is wrong whenever the broker's cap on pending challenges per key is
// what actually answered: portcullis mints a throwaway challenge once a key
// has too many pending, so the token leg 401s with the SAME body
// ({"error":"unauthenticated","detail":"attestation failed"}) as a genuinely
// unenrolled key — deliberately, to preserve the no-enumeration-oracle
// property, so today the two causes are not distinguishable from the
// response alone. Measured 2026-09-14 on atlas: one `nixos-rebuild switch`
// started 17 concurrent `signet vend-to-file` processes against one key, the
// broker's cap of ten pending challenges refused the other seven, every key
// WAS enrolled, and a one-second wait would have cleared it — but the old
// wording sent the reader hunting an enrolment problem that did not exist.
// So the hint quotes the broker's own words and names both live causes
// rather than picking one; narrow it back to a single cause only once the
// broker answers a cap hit with a response this can branch on (tracked as a
// signet follow-up, not yet shipped).
func attestRejectedHint(be *BrokerError) string {
	return fmt.Sprintf(
		"broker refused this attestation (%s) — not enrolled for this identity, "+
			"or too many challenges pending for this key: retry in a moment. "+
			"--identity selects which local key signs; --key overrides its file path directly",
		vendBrokerDetail([]byte(be.Body)),
	)
}

// canonicalMessage constructs the UTF-8 message the broker's canonical form
// prescribes: "{challenge_id}.{nonce}".
// This is the string that must be SHA-256 digested and signed.
func canonicalMessage(challengeID, nonce string) string {
	return challengeID + "." + nonce
}

// Retry tuning for the broker's two advisory 429s on the attest legs
// (portcullis errors.py: `challenge_cap` from POST /v1/attest/token when a
// proven per-key challenge-cap hit clears on its own; `rate_limited` from the
// app-wide limiter ahead of any route). Both say "wait and retry"; `auth_locked`
// (429, a tripped auth-failure lock) and every 401 say "this will not clear by
// waiting" and are never retried here — same rule bearer.go's vendCredential
// already applies to the vend door's 429.
const (
	maxAttestAttempts   = 3                // one send plus up to two retries
	defaultRetryAfter   = 2 * time.Second  // portcullis's own advisory default (CHALLENGE_CAP_RETRY_AFTER_SECONDS)
	maxSingleRetryAfter = 10 * time.Second // cap on any one wait, however large the header claims
	maxTotalRetryWait   = 20 * time.Second // ceiling on waits summed across one call's retries
)

// sleepFunc is time.Sleep, indirected so tests can run the retry loop without
// actually waiting.
var sleepFunc = time.Sleep

// retryableBrokerCode reports whether a 429's error code clears on its own.
func retryableBrokerCode(code string) bool {
	return code == "challenge_cap" || code == "rate_limited"
}

// retryAfterWait parses a Retry-After header (seconds, the only form portcullis
// sends) into a wait duration, falling back to defaultRetryAfter when the
// header is absent or unparseable, and clamping to maxSingleRetryAfter.
func retryAfterWait(header string) time.Duration {
	if header == "" {
		return defaultRetryAfter
	}
	secs, err := strconv.Atoi(strings.TrimSpace(header))
	if err != nil || secs < 0 {
		return defaultRetryAfter
	}
	wait := time.Duration(secs) * time.Second
	if wait > maxSingleRetryAfter {
		return maxSingleRetryAfter
	}
	return wait
}

// brokerPost sends a POST request with a JSON body to endpoint and decodes the
// JSON response into result. If bearerKey is non-empty, it is sent as an
// Authorization: Bearer header. A non-2xx response returns a *BrokerError.
//
// A 429 coded `challenge_cap` or `rate_limited` is retried in place, waiting
// the broker's advertised Retry-After (or defaultRetryAfter absent one),
// bounded by maxAttestAttempts and maxTotalRetryWait; any other status, or a
// 429 with any other code (notably `auth_locked`, and every 401), returns
// immediately exactly as before.
func brokerPost(endpoint string, body any, bearerKey string, result any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	var totalWait time.Duration
	for attempt := 1; ; attempt++ {
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
		respBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("read response: %w", readErr)
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			be := &BrokerError{Status: resp.StatusCode, Body: strings.TrimSpace(string(respBody))}
			if resp.StatusCode != http.StatusTooManyRequests || attempt >= maxAttestAttempts {
				return be
			}
			var f brokerErrorFields
			_ = json.Unmarshal(respBody, &f)
			if !retryableBrokerCode(f.Error) {
				return be
			}
			wait := retryAfterWait(resp.Header.Get("Retry-After"))
			if totalWait+wait > maxTotalRetryWait {
				return be
			}
			totalWait += wait
			fmt.Fprintf(os.Stderr, "signet: broker %s, retrying in %s (attempt %d/%d)\n",
				vendBrokerDetail(respBody), wait, attempt, maxAttestAttempts-1)
			sleepFunc(wait)
			continue
		}

		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
		return nil
	}
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
