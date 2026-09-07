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

// parseBind splits a "<socket>=<slot>" binding. The separator is the last '='
// so socket paths are unconstrained (slot names never contain '=').
func parseBind(s string) (socket, slot string, err error) {
	i := strings.LastIndex(s, "=")
	if i < 0 {
		return "", "", fmt.Errorf("invalid --bind %q; want <socket>=<slot> (e.g. /run/signet/bd.sock=9c)", s)
	}
	socket, slot = s[:i], s[i+1:]
	if socket == "" || slot == "" {
		return "", "", fmt.Errorf("invalid --bind %q; want <socket>=<slot> (e.g. /run/signet/bd.sock=9c)", s)
	}
	return socket, slot, nil
}

// Run starts the agent: one listener per "<socket>=<slot>" binding, all
// sharing a single hardware mutex, until a termination signal arrives.
func Run(backend string, binds []string) error {
	if len(binds) == 0 {
		return fmt.Errorf("signet agent: at least one --bind <socket>=<slot> is required")
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
		socket, slot, err := parseBind(raw)
		if err != nil {
			cleanup()
			return err
		}
		s, err := signer.New(backend, slot, "")
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
		fmt.Fprintf(os.Stderr, "signet agent: serving %s (backend %s, slot %s)\n", socket, backend, slot)
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

// serve accepts connections on ln and handles each with s, which is pinned to
// this listener's slot. Returns when ln is closed (shutdown).
func serve(ln net.Listener, s signer.Signer, hw *sync.Mutex) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed on shutdown
		}
		go handleConn(conn, s, hw)
	}
}

// handleConn reads one request, performs the bound op under the hardware
// mutex, and writes one response. The slot is the listener's, never the client's.
func handleConn(conn net.Conn, s signer.Signer, hw *sync.Mutex) {
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
		hw.Lock()
		pub, err := s.PublicKeyDER()
		hw.Unlock()
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
