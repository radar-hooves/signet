// stampede_test.go: the end-to-end regression guard for the atlas incident
// (radar-hooves/master-project#321) — a Claude Code session start fanning out
// dozens of `signet headers` helpers against one signet-agent at the same
// instant. Every one needs the SAME bearer and the SAME public key; this
// proves the herd now costs the card exactly one open of each, whatever N is,
// with every caller still succeeding.
package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/radar-hooves/signet/internal/attest"
)

// stampedeBroker serves the two attest legs and the credential-vend door,
// counting hits on the attest legs so the test can assert the mint itself
// (not just the hardware) was single-flighted.
type stampedeBroker struct {
	server    *httptest.Server
	challenge atomic.Int32
	token     atomic.Int32
	mintedKey atomic.Value // string
}

func newStampedeBroker(t *testing.T) *stampedeBroker {
	t.Helper()
	b := &stampedeBroker{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/attest/challenge", func(w http.ResponseWriter, _ *http.Request) {
		b.challenge.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"challenge_id": "ch-stampede",
			"nonce":        "noncestampede",
			"expires_at":   time.Now().Add(5 * time.Minute).Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/v1/attest/token", func(w http.ResponseWriter, _ *http.Request) {
		b.token.Add(1)
		const key = "stampede-bearer-key"
		b.mintedKey.Store(key)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"key":            key,
			"key_id":         "kid-s1",
			"name":           "stampede-identity",
			"expires_at":     time.Now().Add(2 * time.Hour).Format(time.RFC3339),
			"max_expires_at": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/v1/credentials/", func(w http.ResponseWriter, r *http.Request) {
		want, _ := b.mintedKey.Load().(string)
		if want == "" || r.Header.Get("Authorization") != "Bearer "+want {
			http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"material":{"kind":"static","fields":[{"name":"api_key","value":"vended"}]}}`))
	})
	b.server = httptest.NewServer(mux)
	t.Cleanup(b.server.Close)
	return b
}

// TestStampede_60ConcurrentHeadersOneCardOpen is the scenario measured on
// atlas 25/09/2026: a session start fans out ~60 `signet headers` processes at
// once, one per gate-served MCP server row, all through one signet-agent. A
// fake broker (a cold cache: no round trip has happened yet) and a fake card
// that errors on a concurrent open must still produce exactly one attestation
// and exactly one hardware open of each kind, with all 60 callers succeeding —
// the failure this replaces was 12 of 88 succeeding, the rest reading the
// helper's silence as "does not support dynamic client registration".
func TestStampede_60ConcurrentHeadersOneCardOpen(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	broker := newStampedeBroker(t)
	card := &cardOpenSigner{name: "atlas", pubkeyDER: stubSPKI}
	var hw sync.Mutex
	client := startAgent(t, card, &hw)

	const n = 60
	var wg sync.WaitGroup
	codes := make([]int, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i], errs[i] = attest.Headers(client, broker.server.URL, "some-cred", "Authorization", "bearer", false)
		}(i)
	}
	wg.Wait()

	for i := range n {
		if errs[i] != nil {
			t.Errorf("caller %d: unexpected error: %v", i, errs[i])
		}
		if codes[i] != attest.ExitHeadersOK {
			t.Errorf("caller %d: exit code = %d, want %d (ExitHeadersOK)", i, codes[i], attest.ExitHeadersOK)
		}
	}
	if got := broker.challenge.Load(); got != 1 {
		t.Errorf("broker challenge calls = %d, want exactly 1 across %d concurrent headers calls", got, n)
	}
	if got := broker.token.Load(); got != 1 {
		t.Errorf("broker token calls = %d, want exactly 1 across %d concurrent headers calls", got, n)
	}
	if got := atomic.LoadInt32(&card.pubkeyOpens); got != 1 {
		t.Errorf("card pubkey opens = %d, want exactly 1 across %d concurrent headers calls", got, n)
	}
	if got := atomic.LoadInt32(&card.signOpens); got != 1 {
		t.Errorf("card sign opens = %d, want exactly 1 across %d concurrent headers calls", got, n)
	}
}
