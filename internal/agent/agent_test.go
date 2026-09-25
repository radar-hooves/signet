package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/radar-hooves/signet/internal/signer"
)

// stubSigner is a hardware-free Signer for the agent tests. It tags its outputs
// with a name so a test can tell which bound signer answered, and tracks peak
// concurrency to prove the agent serialises hardware access.
type stubSigner struct {
	name      string
	signErr   error
	mu        sync.Mutex
	active    int
	maxActive int
}

func (s *stubSigner) Enrol(userPresence bool) (string, error) { return "PUB_" + s.name, nil }
func (s *stubSigner) PublicKeyDER() (string, error)           { return "PUB_" + s.name, nil }

func (s *stubSigner) Sign(message string) (string, error) {
	if s.signErr != nil {
		return "", s.signErr
	}
	s.mu.Lock()
	s.active++
	if s.active > s.maxActive {
		s.maxActive = s.active
	}
	s.mu.Unlock()
	time.Sleep(10 * time.Millisecond) // widen the window for a concurrency race to show
	s.mu.Lock()
	s.active--
	s.mu.Unlock()
	return "SIG_" + s.name + ":" + message, nil
}

var sockCounter int64

// startAgent serves s on a fresh short-path Unix socket and returns a client
// bound to it. Short /tmp paths stay under the macOS sun_path limit (~104 bytes).
func startAgent(t *testing.T, s signer.Signer, hw *sync.Mutex) *Client {
	t.Helper()
	n := atomic.AddInt64(&sockCounter, 1)
	sock := filepath.Join("/tmp", fmt.Sprintf("signet-test-%d-%d.sock", os.Getpid(), n))
	ln, err := listenUnix(sock)
	if err != nil {
		t.Fatalf("listenUnix: %v", err)
	}
	go serve(ln, s, hw)
	t.Cleanup(func() {
		ln.Close()
		os.Remove(sock)
	})
	return NewClient(sock)
}

func TestAgentPubkeyEnrolAndSign(t *testing.T) {
	var hw sync.Mutex
	client := startAgent(t, &stubSigner{name: "A"}, &hw)

	pub, err := client.PublicKeyDER()
	if err != nil || pub != "PUB_A" {
		t.Fatalf("PublicKeyDER = %q, %v; want PUB_A", pub, err)
	}
	// Enrol via the agent returns the existing public key; it must never generate.
	en, err := client.Enrol(false)
	if err != nil || en != "PUB_A" {
		t.Fatalf("Enrol = %q, %v; want PUB_A", en, err)
	}
	sig, err := client.Sign("chal.nonce")
	if err != nil || sig != "SIG_A:chal.nonce" {
		t.Fatalf("Sign = %q, %v; want SIG_A:chal.nonce", sig, err)
	}
}

func TestAgentSlotBindingIsSocketNotClient(t *testing.T) {
	// Two sockets bound to two different signers (= two slots). A client on socket
	// A must only ever get signer A: the slot is fixed by the socket, and the wire
	// protocol carries no slot a client could use to reach across to B.
	var hw sync.Mutex
	a := startAgent(t, &stubSigner{name: "A"}, &hw)
	b := startAgent(t, &stubSigner{name: "B"}, &hw)

	if sa, err := a.Sign("m"); err != nil || sa != "SIG_A:m" {
		t.Fatalf("socket A signed as %q, %v; want SIG_A:m", sa, err)
	}
	if sb, err := b.Sign("m"); err != nil || sb != "SIG_B:m" {
		t.Fatalf("socket B signed as %q, %v; want SIG_B:m", sb, err)
	}
}

func TestAgentSerialisesHardwareAccess(t *testing.T) {
	var hw sync.Mutex
	stub := &stubSigner{name: "A"}
	client := startAgent(t, stub, &hw)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := client.Sign(fmt.Sprintf("m%d", i)); err != nil {
				t.Errorf("Sign: %v", err)
			}
		}(i)
	}
	wg.Wait()

	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.maxActive != 1 {
		t.Fatalf("hardware access not serialised: peak concurrency %d, want 1", stub.maxActive)
	}
}

func TestAgentEmptyMessageAndSignerErrorFailClosed(t *testing.T) {
	var hw sync.Mutex
	client := startAgent(t, &stubSigner{name: "A"}, &hw)
	if _, err := client.Sign(""); err == nil {
		t.Fatal("Sign with empty message should error")
	}

	var hw2 sync.Mutex
	failing := startAgent(t, &stubSigner{name: "A", signErr: fmt.Errorf("hardware unavailable")}, &hw2)
	if _, err := failing.Sign("m"); err == nil {
		t.Fatal("a signer error must propagate to the client, not be swallowed")
	}
}

func TestAgentDialErrorOnMissingSocket(t *testing.T) {
	client := NewClient("/tmp/signet-test-does-not-exist.sock")
	if _, err := client.Sign("m"); err == nil {
		t.Fatal("Sign against a missing socket should error")
	}
}

// contendedSigner simulates a backend racing an EXTERNAL process (this host's
// SSH agent, in the atlas incident this fix targets) for the same physical
// card, modelled as a CAS-guarded flag shared across all calls. It never
// retries internally — that is piv.go's job, already exhausted by the time a
// real backend would report this — so every failure it returns must be ridden
// out by the CLIENT's own retry (callWithBusyRetry) for a caller to succeed.
type contendedSigner struct {
	name string
	held *int32 // 0 = free, 1 = held by the "external" contender for this instant
}

func (s *contendedSigner) tryClaim() error {
	if !atomic.CompareAndSwapInt32(s.held, 0, 1) {
		return fmt.Errorf("PIV: open %q: card busy (transient PC/SC contention): the smart card cannot be accessed because of other connections outstanding", s.name)
	}
	return nil
}

func (s *contendedSigner) Enrol(bool) (string, error) { return s.PublicKeyDER() }

func (s *contendedSigner) PublicKeyDER() (string, error) {
	if err := s.tryClaim(); err != nil {
		return "", err
	}
	defer atomic.StoreInt32(s.held, 0)
	return "PUB_" + s.name, nil
}

func (s *contendedSigner) Sign(message string) (string, error) {
	if err := s.tryClaim(); err != nil {
		return "", err
	}
	defer atomic.StoreInt32(s.held, 0)
	return "SIG_" + s.name + ":" + message, nil
}

// TestClientRetriesCardBusyThenSucceeds proves a single call rides out a
// bounded number of "card busy" answers from the agent transparently.
func TestClientRetriesCardBusyThenSucceeds(t *testing.T) {
	savedRetries, savedBackoff := clientBusyRetries, clientBusyBackoff
	clientBusyRetries = 5
	clientBusyBackoff = 3 * time.Millisecond // real waits: retries must span the release below
	t.Cleanup(func() { clientBusyRetries, clientBusyBackoff = savedRetries, savedBackoff })

	var hw sync.Mutex
	var held int32 = 1 // start "held" by the external contender
	client := startAgent(t, &contendedSigner{name: "A", held: &held}, &hw)

	// Release the external hold shortly after the client's first attempt would
	// have failed, so the retry (not the first try) is what succeeds.
	go func() {
		time.Sleep(4 * time.Millisecond)
		atomic.StoreInt32(&held, 0)
	}()

	sig, err := client.Sign("m")
	if err != nil {
		t.Fatalf("Sign: want the retry to ride out transient contention, got %v", err)
	}
	if sig != "SIG_A:m" {
		t.Fatalf("Sign = %q, want SIG_A:m", sig)
	}
}

// TestClientBurstSucceedsDespiteExternalContention is the serialisation proof
// this fix exists for: a burst of concurrent requests (a Claude Code session
// fanning out ~85 MCP server spawns) against a card an external process (this
// host's SSH agent) is repeatedly grabbing must ALL succeed, not fail with
// "no key enrolled" or "unexpected error" the way atlas did.
func TestClientBurstSucceedsDespiteExternalContention(t *testing.T) {
	savedRetries, savedBackoff, savedSleep := clientBusyRetries, clientBusyBackoff, clientSleep
	clientBusyRetries = 200 // generous ceiling; no real backoff wait below
	clientBusyBackoff = 0
	clientSleep = func(time.Duration) {}
	t.Cleanup(func() { clientBusyRetries, clientBusyBackoff, clientSleep = savedRetries, savedBackoff, savedSleep })

	var hw sync.Mutex
	var held int32
	client := startAgent(t, &contendedSigner{name: "A", held: &held}, &hw)

	// The external contender: a background goroutine standing in for this
	// host's SSH agent, cycling brief exclusive holds on the same "card" for
	// the whole burst. It yields a "free" window between holds long enough for
	// a real socket round trip to land — a tight, un-throttled spin here would
	// win essentially every race against the socket dial + encode + decode a
	// real request costs, understating how briefly a real contender holds a
	// PC/SC connection.
	stop := make(chan struct{})
	var extWG sync.WaitGroup
	extWG.Add(1)
	go func() {
		defer extWG.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if atomic.CompareAndSwapInt32(&held, 0, 1) {
				time.Sleep(50 * time.Microsecond)
				atomic.StoreInt32(&held, 0)
			}
			time.Sleep(200 * time.Microsecond) // a free window each cycle
		}
	}()

	const n = 90
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = client.Sign(fmt.Sprintf("m%d", i))
		}(i)
	}
	wg.Wait()
	close(stop)
	extWG.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("request %d failed despite retry: %v", i, err)
		}
	}
}

// stubSPKI is a minimal valid base64-encoded SPKI DER for a P-256 public key
// (the same fixture internal/attest's tests use), so a cardOpenSigner can
// stand in for the card in a test that runs the fingerprint/cache path, not
// only the agent's own pubkey/sign RPCs.
const stubSPKI = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAQIDBAUGBwgJCgsMDQ4PEBESExQV" +
	"FhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/"

// cardOpenSigner models physical hardware that cannot be opened twice at
// once: PublicKeyDER and Sign each claim an exclusive "open" and error,
// PC/SC-sharing-violation style, if another call already holds it — the shape
// pivSigner actually has (openFirstYubiKey/yk.Close() per call). It counts
// real opens of each kind so a test can prove the agent needed the hardware
// only once, however many clients asked at once. pubkeyDER, left empty,
// defaults to a "PUB_"+name tag; a test that feeds the answer through
// internal/attest's fingerprint computation sets it to stubSPKI instead.
type cardOpenSigner struct {
	name        string
	pubkeyDER   string
	open        int32
	pubkeyOpens int32
	signOpens   int32
}

func (s *cardOpenSigner) Enrol(bool) (string, error) { return s.PublicKeyDER() }

func (s *cardOpenSigner) PublicKeyDER() (string, error) {
	if !atomic.CompareAndSwapInt32(&s.open, 0, 1) {
		return "", fmt.Errorf("card busy: the smart card cannot be accessed because of other connections outstanding")
	}
	defer atomic.StoreInt32(&s.open, 0)
	atomic.AddInt32(&s.pubkeyOpens, 1)
	time.Sleep(time.Millisecond) // widen the window a real PC/SC open holds
	if s.pubkeyDER != "" {
		return s.pubkeyDER, nil
	}
	return "PUB_" + s.name, nil
}

func (s *cardOpenSigner) Sign(message string) (string, error) {
	if !atomic.CompareAndSwapInt32(&s.open, 0, 1) {
		return "", fmt.Errorf("card busy: the smart card cannot be accessed because of other connections outstanding")
	}
	defer atomic.StoreInt32(&s.open, 0)
	atomic.AddInt32(&s.signOpens, 1)
	time.Sleep(time.Millisecond)
	return "SIG_" + s.name + ":" + message, nil
}

// TestAgentCachesPubkeyAcrossConcurrentClients is the herd-cost proof: a
// session start's fan-out of MCP servers each ask the same agent binding for
// its public key at once. Before the agent memoized the answer, every one of
// those was a fresh hardware read serialised behind hw — cheap for a handful,
// but the cost that let 76 of 88 MCP servers time out on atlas
// (radar-hooves/master-project#321). With memoization, the herd costs the
// hardware exactly one open, however many clients ask, and every client still
// gets the right answer.
func TestAgentCachesPubkeyAcrossConcurrentClients(t *testing.T) {
	var hw sync.Mutex
	card := &cardOpenSigner{name: "A"}
	client := startAgent(t, card, &hw)

	const n = 60
	var wg sync.WaitGroup
	pubs := make([]string, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pubs[i], errs[i] = client.PublicKeyDER()
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("client %d: %v", i, err)
		}
		if pubs[i] != "PUB_A" {
			t.Errorf("client %d pubkey = %q, want PUB_A", i, pubs[i])
		}
	}
	if opens := atomic.LoadInt32(&card.pubkeyOpens); opens != 1 {
		t.Errorf("card pubkey opens = %d, want exactly 1 across %d concurrent clients", opens, n)
	}

	// A later, sequential caller must still get the cached answer, not a fresh
	// hardware read: the memo holds for the binding's whole lifetime.
	pub, err := client.PublicKeyDER()
	if err != nil || pub != "PUB_A" {
		t.Fatalf("later PublicKeyDER = %q, %v; want PUB_A, nil", pub, err)
	}
	if opens := atomic.LoadInt32(&card.pubkeyOpens); opens != 1 {
		t.Errorf("card pubkey opens after a later call = %d, want still 1", opens)
	}
}

// TestAgentPubkeyCacheNotPoisonedByFailure proves a failed fetch is not
// memoized: IsCardBusy answers must stay retryable (client.go's
// callWithBusyRetry depends on this), never permanently poisoned by one
// transient refusal.
func TestAgentPubkeyCacheNotPoisonedByFailure(t *testing.T) {
	var hw sync.Mutex
	card := &cardOpenSigner{name: "A"}
	atomic.StoreInt32(&card.open, 1) // pre-held: the first fetch must fail
	client := startAgent(t, card, &hw)

	if _, err := client.PublicKeyDER(); err == nil {
		t.Fatal("PublicKeyDER: want an error while the card is held, got nil")
	}
	atomic.StoreInt32(&card.open, 0) // released, as a transient contender would

	pub, err := client.PublicKeyDER()
	if err != nil || pub != "PUB_A" {
		t.Fatalf("PublicKeyDER after release = %q, %v; want PUB_A, nil — a failed fetch must not be cached", pub, err)
	}
}

func TestParseBind(t *testing.T) {
	sock, slot, err := parseBind("/run/signet/bd.sock=9c")
	if err != nil || sock != "/run/signet/bd.sock" || slot != "9c" {
		t.Fatalf("parseBind = %q, %q, %v; want /run/signet/bd.sock, 9c, nil", sock, slot, err)
	}
	for _, bad := range []string{"", "noequals", "=9c", "/sock="} {
		if _, _, err := parseBind(bad); err == nil {
			t.Errorf("parseBind(%q) should error", bad)
		}
	}
}
