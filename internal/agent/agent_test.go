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
