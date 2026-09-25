// server.go: the serve side of the signet agent — one listener per binding,
// all sharing a single hardware mutex.
package agent

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/radar-hooves/signet/internal/signer"
)

// parseBind splits a "<socket>=<key>" binding. The separator is the last '='
// so socket paths are unconstrained (a PIV slot or TPM/Secure-Enclave
// identity never contains '='). key means a PIV slot under --backend piv, or
// an identity name under --backend tpm / secure-enclave — see Run.
func parseBind(s string) (socket, key string, err error) {
	i := strings.LastIndex(s, "=")
	if i < 0 {
		return "", "", fmt.Errorf("invalid --bind %q; want <socket>=<slot-or-identity> (e.g. /run/signet/bd.sock=9c for piv, /run/signet/deploy.sock=deploy for tpm/secure-enclave)", s)
	}
	socket, key = s[:i], s[i+1:]
	if socket == "" || key == "" {
		return "", "", fmt.Errorf("invalid --bind %q; want <socket>=<slot-or-identity> (e.g. /run/signet/bd.sock=9c for piv, /run/signet/deploy.sock=deploy for tpm/secure-enclave)", s)
	}
	return socket, key, nil
}

// Run starts the agent: one listener per "<socket>=<key>" binding, all
// sharing a single hardware mutex, until a termination signal arrives.
//
// Each binding's key is passed to signer.New as BOTH slot and identity: every
// backend reads only the one of those two params it understands (piv reads
// slot, tpm and secure-enclave read identity) and ignores the other, so the
// binding's meaning follows backend without any switch here. A key that is
// the wrong shape for the chosen backend is refused loudly by that backend's
// own constructor — an unrecognised PIV slot today, or (on tpm/secure-enclave)
// signing against a never-enrolled identity at first use — never silently
// reinterpreted or collapsed onto another binding's key.
func Run(backend string, binds []string) error {
	if len(binds) == 0 {
		return fmt.Errorf("signet agent: at least one --bind <socket>=<slot-or-identity> is required")
	}

	var hw sync.Mutex // serialises every hardware access (the token is single-access)
	var listeners []net.Listener
	var sockets []string
	var wg sync.WaitGroup

	// Tear down anything already opened if a later binding fails to start.
	cleanup := func() {
		for _, ln := range listeners {
			ln.Close()
		}
		for _, s := range sockets {
			os.Remove(s)
		}
	}

	for _, raw := range binds {
		socket, key, err := parseBind(raw)
		if err != nil {
			cleanup()
			return err
		}
		s, err := signer.New(backend, key, key)
		if err != nil {
			cleanup()
			return fmt.Errorf("bind %s: %w", socket, err)
		}
		ln, err := listenUnix(socket)
		if err != nil {
			cleanup()
			return err
		}
		listeners = append(listeners, ln)
		sockets = append(sockets, socket)
		wg.Add(1)
		go func(ln net.Listener, s signer.Signer) {
			defer wg.Done()
			serve(ln, s, &hw)
		}(ln, s)
		fmt.Fprintf(os.Stderr, "signet agent: serving %s (backend %s, key %s)\n", socket, backend, key)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	fmt.Fprintln(os.Stderr, "signet agent: shutting down")

	for _, ln := range listeners {
		ln.Close() // unblocks the Accept loops
	}
	wg.Wait()
	for _, s := range sockets {
		os.Remove(s)
	}
	return nil
}

// listenUnix removes a stale socket from a previous run, binds it, and tightens
// its mode so only the owner and a shared group can reach it.
func listenUnix(socket string) (net.Listener, error) {
	if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove stale socket %s: %w", socket, err)
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", socket, err)
	}
	if err := os.Chmod(socket, socketMode); err != nil {
		ln.Close()
		os.Remove(socket)
		return nil, fmt.Errorf("chmod %s: %w", socket, err)
	}
	return ln, nil
}

// pubkeyCache memoizes one binding's PublicKeyDER answer. The enrolled key for
// a fixed slot/identity cannot change without an agent restart, so once
// hardware has answered once there is no reason for a later request — however
// many arrive at once — to reopen the card at all: a session start's fan-out
// of MCP servers needs this same answer dozens of times a minute apart from
// the one broker round trip that actually needs a fresh signature.
//
// A failed fetch is deliberately NOT cached: openFirstYubiKey already rides
// out a transient PC/SC sharing violation internally before answering, and a
// caller still seeing IsCardBusy after that must be free to retry against
// real hardware again, not read the same failure back forever.
type pubkeyCache struct {
	mu     sync.Mutex
	cached bool
	der    string
}

// get returns the memoized public key, fetching it under hw at most once.
// Concurrent misses serialise on c.mu rather than hw, so a cold start costs
// exactly one hardware read however many clients ask at the same instant, and
// a hit never contends with an in-flight sign at all.
func (c *pubkeyCache) get(s signer.Signer, hw *sync.Mutex) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cached {
		return c.der, nil
	}
	hw.Lock()
	der, err := s.PublicKeyDER()
	hw.Unlock()
	if err != nil {
		return "", err
	}
	c.der, c.cached = der, true
	return c.der, nil
}

// serve accepts connections on ln and handles each with s, which is pinned to
// this listener's key (slot or identity). Returns when ln is closed (shutdown).
func serve(ln net.Listener, s signer.Signer, hw *sync.Mutex) {
	cache := &pubkeyCache{}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed on shutdown
		}
		go handleConn(conn, s, hw, cache)
	}
}

// handleConn reads one request, performs the bound op under the hardware
// mutex, and writes one response. The key is the listener's, never the client's.
func handleConn(conn net.Conn, s signer.Signer, hw *sync.Mutex, cache *pubkeyCache) {
	defer conn.Close()
	_ = conn.SetDeadline(timeNow().Add(connTimeout))

	var req request
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&req); err != nil {
		writeResponse(conn, response{Error: "invalid request: " + err.Error()})
		return
	}

	var resp response
	switch req.Op {
	case "pubkey":
		pub, err := cache.get(s, hw)
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.PublicKeyDER = pub
		}
	case "sign":
		if req.Message == "" {
			resp.Error = "sign requires a non-empty message"
			break
		}
		hw.Lock()
		sig, err := s.Sign(req.Message)
		hw.Unlock()
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.SignatureB64 = sig
		}
	default:
		resp.Error = fmt.Sprintf("unknown op %q (want pubkey | sign)", req.Op)
	}
	writeResponse(conn, resp)
}

func writeResponse(conn net.Conn, resp response) {
	b, err := json.Marshal(resp)
	if err != nil {
		return
	}
	_, _ = conn.Write(append(b, '\n'))
}
