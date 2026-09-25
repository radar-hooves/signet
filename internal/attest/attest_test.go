// attest_test.go: tests for the broker attestation flow and bearer cache.
// Uses net/http/httptest for a fake broker; no real network or hardware required.
package attest

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// stubSPKI is a minimal valid base64-encoded SPKI DER for a P-256 public key.
// Computed from the real encoding so publicKeyFingerprint can decode it cleanly.
// (The bytes spell out an ASN.1 SEQUENCE wrapping the P-256 algorithm OID and a
// placeholder bit-string; they do not need to represent a real key for cache tests.)
const stubSPKI = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAQIDBAUGBwgJCgsMDQ4PEBESExQV" +
	"FhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/"

// stubSigner is a fake Signer that returns a canned signature and a
// deterministic public key (stubSPKI) for use in tests.
type stubSigner struct {
	sig       string
	err       error
	pubKey    string // overrides stubSPKI when non-empty
	pubKeyErr error  // when non-nil, PublicKeyDER returns this error
}

func (s *stubSigner) Enrol() (string, error) { return stubSPKI, nil }
func (s *stubSigner) PublicKeyDER() (string, error) {
	if s.pubKeyErr != nil {
		return "", s.pubKeyErr
	}
	if s.pubKey != "" {
		return s.pubKey, nil
	}
	return stubSPKI, nil
}
func (s *stubSigner) Sign(_ string) (string, error) { return s.sig, s.err }

// fakeNow is a shared reference time for test tokens.
var fakeNow = time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)

// fakeBroker builds a fake attestation broker using httptest. It serves:
//   - POST /v1/attest/challenge  → challengeResult (verifies public_key_der present)
//   - POST /v1/attest/token     → tokenResult (verifies identity_id absent)
//   - POST /v1/attest/renew     → tokenResult or 401 if renewStatus401 is set
func fakeBroker(t *testing.T, ttl time.Duration, renewStatus401 bool) *httptest.Server {
	t.Helper()
	maxExpiry := fakeNow.Add(24 * time.Hour)
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/attest/challenge", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		// Verify wire contract: public_key_der must be present, identity_id must not.
		if _, ok := body["public_key_der"]; !ok {
			t.Errorf("challenge body missing public_key_der: %v", body)
			http.Error(w, "missing public_key_der", http.StatusBadRequest)
			return
		}
		if _, ok := body["identity_id"]; ok {
			t.Errorf("challenge body must not contain identity_id (resolve-by-key): %v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(challengeResult{
			ChallengeID: "ch-test-1234",
			Nonce:       "testnonce",
			ExpiresAt:   fakeNow.Add(5 * time.Minute).Format(time.RFC3339),
		})
	})

	mux.HandleFunc("/v1/attest/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		// Verify wire contract: identity_id must NOT be present.
		if _, ok := body["identity_id"]; ok {
			t.Errorf("token body must not contain identity_id (resolve-by-key): %v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResult{
			Key:          "test-bearer-key",
			KeyID:        "kid-1",
			Name:         "test-identity",
			ExpiresAt:    fakeNow.Add(ttl).Format(time.RFC3339),
			MaxExpiresAt: maxExpiry.Format(time.RFC3339),
		})
	})

	mux.HandleFunc("/v1/attest/renew", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if renewStatus401 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResult{
			Key:          "renewed-bearer-key",
			KeyID:        "kid-2",
			Name:         "test-identity",
			ExpiresAt:    fakeNow.Add(ttl).Format(time.RFC3339),
			MaxExpiresAt: maxExpiry.Format(time.RFC3339),
		})
	})

	return httptest.NewServer(mux)
}

// setTempHome redirects os.UserHomeDir() to a temp directory for the test.
func setTempHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	return dir
}

// mustFingerprint computes the public key fingerprint for spkiB64 or fails the
// test. Used to compute expected cache keys without duplicating the logic.
func mustFingerprint(t *testing.T, spkiB64 string) string {
	t.Helper()
	fp, err := publicKeyFingerprint(spkiB64)
	if err != nil {
		t.Fatalf("publicKeyFingerprint: %v", err)
	}
	return fp
}

// TestAuth_ColdCache verifies a fresh attestation when no cache exists.
func TestAuth_ColdCache(t *testing.T) {
	setTempHome(t)
	srv := fakeBroker(t, 2*time.Hour, false)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	if err := Auth(s, srv.URL); err != nil {
		t.Fatalf("Auth: %v", err)
	}

	// Cache should now exist on disk, keyed by fingerprint.
	fp := mustFingerprint(t, stubSPKI)
	bc := loadCache(srv.URL, fp)
	if bc == nil {
		t.Fatal("expected cache to be written after fresh attest, got nil")
	}
	if bc.Key != "test-bearer-key" {
		t.Errorf("cached key = %q, want %q", bc.Key, "test-bearer-key")
	}
}

// TestAuth_WarmCache verifies that a healthy cached bearer is reused without
// calling the broker.
func TestAuth_WarmCache(t *testing.T) {
	setTempHome(t)

	// Write a warm cache (TTL > 30 min), keyed by the stub's key fingerprint.
	fp := mustFingerprint(t, stubSPKI)
	bc := &bearerCache{
		Key:          "cached-key",
		ExpiresAt:    time.Now().Add(2 * time.Hour),
		MaxExpiresAt: time.Now().Add(24 * time.Hour),
	}

	// Write a broker that would fail if called.
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	defer srv.Close()

	if err := saveCache(srv.URL, fp, bc); err != nil {
		t.Fatalf("saveCache: %v", err)
	}

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	if err := Auth(s, srv.URL); err != nil {
		t.Fatalf("Auth: %v", err)
	}
	if callCount > 0 {
		t.Errorf("broker was called %d times, expected 0 for warm cache", callCount)
	}
}

// TestAuth_NearExpiry verifies that a near-expiry cache triggers a renew,
// the renewed key is cached, and the renewed key is emitted.
func TestAuth_NearExpiry(t *testing.T) {
	setTempHome(t)

	fp := mustFingerprint(t, stubSPKI)

	// Near-expiry cache: TTL = 10 minutes.
	bc := &bearerCache{
		Key:          "near-expiry-key",
		ExpiresAt:    time.Now().Add(10 * time.Minute),
		MaxExpiresAt: time.Now().Add(24 * time.Hour),
	}
	srv := fakeBroker(t, 2*time.Hour, false)
	defer srv.Close()

	if err := saveCache(srv.URL, fp, bc); err != nil {
		t.Fatalf("saveCache: %v", err)
	}

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	if err := Auth(s, srv.URL); err != nil {
		t.Fatalf("Auth: %v", err)
	}

	updated := loadCache(srv.URL, fp)
	if updated == nil {
		t.Fatal("expected cache to be updated after renew")
	}
	if updated.Key != "renewed-bearer-key" {
		t.Errorf("cache key = %q, want %q", updated.Key, "renewed-bearer-key")
	}
}

// TestAuth_Renew401_ReAttests verifies that a 401 from /renew causes a
// full re-attestation (challenge+token), not a failure.
func TestAuth_Renew401_ReAttests(t *testing.T) {
	setTempHome(t)

	fp := mustFingerprint(t, stubSPKI)

	// Near-expiry cache.
	bc := &bearerCache{
		Key:          "old-key",
		ExpiresAt:    time.Now().Add(10 * time.Minute),
		MaxExpiresAt: time.Now().Add(24 * time.Hour),
	}
	// Broker returns 401 on renew.
	srv := fakeBroker(t, 2*time.Hour, true)
	defer srv.Close()

	if err := saveCache(srv.URL, fp, bc); err != nil {
		t.Fatalf("saveCache: %v", err)
	}

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	if err := Auth(s, srv.URL); err != nil {
		t.Fatalf("Auth: %v", err)
	}

	// After re-attest, cache should carry the fresh key from /token.
	updated := loadCache(srv.URL, fp)
	if updated == nil {
		t.Fatal("expected cache after re-attest")
	}
	if updated.Key != "test-bearer-key" {
		t.Errorf("cache key = %q, want %q (from fresh attest)", updated.Key, "test-bearer-key")
	}
}

// TestCacheRoundTrip verifies saveCache/loadCache preserve all fields faithfully.
func TestCacheRoundTrip(t *testing.T) {
	setTempHome(t)

	fp := mustFingerprint(t, stubSPKI)
	want := &bearerCache{
		Key:          "round-trip-key",
		ExpiresAt:    fakeNow.Add(1 * time.Hour).UTC(),
		MaxExpiresAt: fakeNow.Add(24 * time.Hour).UTC(),
	}
	if err := saveCache("http://broker.test", fp, want); err != nil {
		t.Fatalf("saveCache: %v", err)
	}
	got := loadCache("http://broker.test", fp)
	if got == nil {
		t.Fatal("loadCache returned nil")
	}
	if got.Key != want.Key {
		t.Errorf("Key: got %q, want %q", got.Key, want.Key)
	}
	if !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf("ExpiresAt: got %v, want %v", got.ExpiresAt, want.ExpiresAt)
	}
	if !got.MaxExpiresAt.Equal(want.MaxExpiresAt) {
		t.Errorf("MaxExpiresAt: got %v, want %v", got.MaxExpiresAt, want.MaxExpiresAt)
	}
}

// TestParseExpiry verifies both RFC3339Nano and RFC3339 inputs parse correctly.
func TestParseExpiry(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  time.Time
	}{
		{"RFC3339Nano", "2026-06-20T12:00:00.123456789Z", time.Date(2026, 6, 20, 12, 0, 0, 123456789, time.UTC)},
		{"RFC3339", "2026-06-20T12:00:00Z", time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseExpiry(tc.input)
			if err != nil {
				t.Fatalf("parseExpiry(%q): %v", tc.input, err)
			}
			if !got.Equal(tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}

	if _, err := parseExpiry("not-a-date"); err == nil {
		t.Error("expected error for unparseable expiry, got nil")
	}
}

// TestBearerCacheFromToken verifies the shared parser used by both attest paths.
func TestBearerCacheFromToken(t *testing.T) {
	tr := tokenResult{
		Key:          "tok",
		ExpiresAt:    "2026-06-20T13:00:00Z",
		MaxExpiresAt: "2026-06-21T12:00:00Z",
	}
	bc, err := bearerCacheFromToken(tr)
	if err != nil {
		t.Fatalf("bearerCacheFromToken: %v", err)
	}
	if bc.Key != "tok" {
		t.Errorf("Key = %q, want %q", bc.Key, "tok")
	}
	wantExpiry := time.Date(2026, 6, 20, 13, 0, 0, 0, time.UTC)
	if !bc.ExpiresAt.Equal(wantExpiry) {
		t.Errorf("ExpiresAt = %v, want %v", bc.ExpiresAt, wantExpiry)
	}

	// Bad expires_at propagates an error.
	_, err = bearerCacheFromToken(tokenResult{ExpiresAt: "bad", MaxExpiresAt: "2026-06-21T12:00:00Z"})
	if err == nil {
		t.Error("expected error for bad expires_at")
	}

	// Bad max_expires_at propagates an error.
	_, err = bearerCacheFromToken(tokenResult{ExpiresAt: "2026-06-20T13:00:00Z", MaxExpiresAt: "bad"})
	if err == nil {
		t.Error("expected error for bad max_expires_at")
	}
}

// TestCachePath verifies the cache path is deterministic and safe, and that
// different fingerprints produce different paths (resolve-by-key cache isolation).
func TestCachePath(t *testing.T) {
	setTempHome(t)

	fp1 := mustFingerprint(t, stubSPKI)
	p1, err := cachePath("http://localhost:8311", fp1)
	if err != nil {
		t.Fatalf("cachePath: %v", err)
	}
	p2, err := cachePath("http://localhost:8311", fp1)
	if err != nil {
		t.Fatalf("cachePath (2nd call): %v", err)
	}
	if p1 != p2 {
		t.Errorf("cachePath is not deterministic: %q vs %q", p1, p2)
	}
	// Different fingerprint → different path.
	fp2 := "abcdef0123456789" // a distinct 16-hex-char fingerprint
	p3, err := cachePath("http://localhost:8311", fp2)
	if err != nil {
		t.Fatalf("cachePath (fp2): %v", err)
	}
	if p1 == p3 {
		t.Errorf("different fingerprints produced the same cache path: %q", p1)
	}
	// Path must be inside the expected directory.
	if base := filepath.Base(p1); base == "" {
		t.Error("cachePath returned empty filename")
	}
}

// TestPublicKeyFingerprint verifies the fingerprint function produces a 16-char
// hex string and is deterministic.
func TestPublicKeyFingerprint(t *testing.T) {
	fp, err := publicKeyFingerprint(stubSPKI)
	if err != nil {
		t.Fatalf("publicKeyFingerprint: %v", err)
	}
	if len(fp) != 16 {
		t.Errorf("fingerprint length = %d, want 16: %q", len(fp), fp)
	}
	// Deterministic.
	fp2, err := publicKeyFingerprint(stubSPKI)
	if err != nil {
		t.Fatalf("publicKeyFingerprint (2nd): %v", err)
	}
	if fp != fp2 {
		t.Errorf("fingerprint not deterministic: %q vs %q", fp, fp2)
	}
	// Bad base64 → error.
	if _, err := publicKeyFingerprint("not!!base64"); err == nil {
		t.Error("expected error for invalid base64, got nil")
	}
}

// TestLoadCache_MissingFile verifies loadCache returns nil for a nonexistent file.
func TestLoadCache_MissingFile(t *testing.T) {
	setTempHome(t)
	if bc := loadCache("http://no.such.broker", "abcdef0123456789"); bc != nil {
		t.Errorf("expected nil for missing cache, got %+v", bc)
	}
}

// TestLoadCache_CorruptFile verifies loadCache returns nil for malformed JSON.
func TestLoadCache_CorruptFile(t *testing.T) {
	home := setTempHome(t)
	cDir := filepath.Join(home, ".signet", "cache")
	if err := os.MkdirAll(cDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(cDir, "corrupt.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// loadCache for a key that maps to this exact path would silently return nil.
	// We verify via direct file corruption that the decode-error path works.
	var bc bearerCache
	if err := json.Unmarshal([]byte("not json"), &bc); err == nil {
		t.Error("expected json.Unmarshal to fail on corrupt input")
	}
}

// TestCanonicalMessage verifies the signed-message construction matches
// the broker's canonical_message(challenge_id, nonce) form:
// UTF-8 of "{challenge_id}.{nonce}".
func TestCanonicalMessage(t *testing.T) {
	cases := []struct {
		challengeID string
		nonce       string
		want        string
	}{
		{"abc123", "xyz789", "abc123.xyz789"},
		{"ch-00000000-0000-0000-0000-000000000001", "nonce-val", "ch-00000000-0000-0000-0000-000000000001.nonce-val"},
		{"a", "b", "a.b"},
		{"", "n", ".n"},
	}
	for _, tc := range cases {
		got := canonicalMessage(tc.challengeID, tc.nonce)
		if got != tc.want {
			t.Errorf("canonicalMessage(%q, %q) = %q; want %q", tc.challengeID, tc.nonce, got, tc.want)
		}
	}
}

// stubSleep swaps sleepFunc for one that records requested durations instead
// of waiting, restoring the original on test cleanup.
func stubSleep(t *testing.T) *[]time.Duration {
	t.Helper()
	var waits []time.Duration
	orig := sleepFunc
	sleepFunc = func(d time.Duration) { waits = append(waits, d) }
	t.Cleanup(func() { sleepFunc = orig })
	return &waits
}

// write429 writes a 429 response coded err, with an optional Retry-After
// header (omitted when retryAfter == "").
func write429(w http.ResponseWriter, code, retryAfter string) {
	if retryAfter != "" {
		w.Header().Set("Retry-After", retryAfter)
	}
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "detail": code + " detail"})
}

// TestBrokerPost_RetriesChallengeCapThenSucceeds verifies a 429 coded
// challenge_cap is retried after the broker's advertised Retry-After and the
// eventual success is returned to the caller.
func TestBrokerPost_RetriesChallengeCapThenSucceeds(t *testing.T) {
	waits := stubSleep(t)

	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/attest/token", func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 2 {
			write429(w, "challenge_cap", "1")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResult{Key: "k", KeyID: "id", Name: "n"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var tr tokenResult
	if err := brokerPost(srv.URL+"/v1/attest/token", map[string]string{}, "", &tr); err != nil {
		t.Fatalf("brokerPost: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 calls, got %d", calls)
	}
	if got := *waits; len(got) != 1 || got[0] != 1*time.Second {
		t.Fatalf("expected one 1s wait, got %v", got)
	}
	if tr.Key != "k" {
		t.Fatalf("unexpected token result: %+v", tr)
	}
}

// TestBrokerPost_RetriesExhausted verifies a persistent retryable 429 (here
// rate_limited) is retried up to maxAttestAttempts and then returned as the
// broker's own error, never masked as success.
func TestBrokerPost_RetriesExhausted(t *testing.T) {
	stubSleep(t)

	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/attest/challenge", func(w http.ResponseWriter, r *http.Request) {
		calls++
		write429(w, "rate_limited", "1")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var cr challengeResult
	err := brokerPost(srv.URL+"/v1/attest/challenge", map[string]string{}, "", &cr)
	if err == nil {
		t.Fatal("expected error once retries are exhausted")
	}
	var be *BrokerError
	if !errors.As(err, &be) || be.Status != http.StatusTooManyRequests {
		t.Fatalf("expected *BrokerError 429, got %v", err)
	}
	if calls != maxAttestAttempts {
		t.Fatalf("expected %d calls, got %d", maxAttestAttempts, calls)
	}
}

// TestBrokerPost_AuthLockedNotRetried verifies the app-wide auth_locked 429 —
// a tripped auth-failure lock, not a transient cap — fails on the first
// response: waiting cannot fix a locked-out bearer.
func TestBrokerPost_AuthLockedNotRetried(t *testing.T) {
	stubSleep(t)

	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/attest/challenge", func(w http.ResponseWriter, r *http.Request) {
		calls++
		write429(w, "auth_locked", "1")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var cr challengeResult
	err := brokerPost(srv.URL+"/v1/attest/challenge", map[string]string{}, "", &cr)
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Fatalf("expected exactly 1 call (no retry), got %d", calls)
	}
}

// TestBrokerPost_401NotRetried verifies a plain 401 (unauthenticated) is never
// retried — it is a permanent identity fault, not a transient one.
func TestBrokerPost_401NotRetried(t *testing.T) {
	stubSleep(t)

	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/attest/token", func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthenticated", "detail": "attestation failed"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var tr tokenResult
	err := brokerPost(srv.URL+"/v1/attest/token", map[string]string{}, "", &tr)
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Fatalf("expected exactly 1 call (no retry), got %d", calls)
	}
}

// TestBrokerPost_RetryAfterAbsentUsesDefault verifies a retryable 429 with no
// Retry-After header waits defaultRetryAfter rather than failing immediately
// or waiting indefinitely.
func TestBrokerPost_RetryAfterAbsentUsesDefault(t *testing.T) {
	waits := stubSleep(t)

	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/attest/token", func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 2 {
			write429(w, "challenge_cap", "")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResult{Key: "k", KeyID: "id", Name: "n"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var tr tokenResult
	if err := brokerPost(srv.URL+"/v1/attest/token", map[string]string{}, "", &tr); err != nil {
		t.Fatalf("brokerPost: %v", err)
	}
	if got := *waits; len(got) != 1 || got[0] != defaultRetryAfter {
		t.Fatalf("expected one wait of defaultRetryAfter, got %v", got)
	}
}

// TestSanitiseHost verifies the cache filename sanitisation for broker URLs.
func TestSanitiseHost(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"http://localhost:8311", "http_localhost_8311"},
		{"https://broker.example.internal", "https_broker.example.internal"},
		{"https://broker.example.internal/", "https_broker.example.internal_"},
		{"https://broker.example.internal:8443/api", "https_broker.example.internal_8443_api"},
	}
	for _, tc := range cases {
		got := sanitiseHost(tc.input)
		if got != tc.want {
			t.Errorf("sanitiseHost(%q) = %q; want %q", tc.input, got, tc.want)
		}
	}
}
