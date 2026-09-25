// client.go: the client side of the signet agent — a Signer that forwards to
// an agent socket instead of opening local hardware.
package agent

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/radar-hooves/signet/internal/signer"
)

// clientBusyRetries and clientBusyBackoff bound a SECOND, outer retry layer:
// openFirstYubiKey (internal/signer/piv.go) already rides out a transient PC/SC
// sharing violation inside the agent before answering, but a contender holding
// the card longer than that window (a slow SSH session sharing the same
// physical YubiKey) still surfaces as the agent's own "card busy, retries
// exhausted" answer. Retrying the whole round trip here — dial, request,
// response — a few more times gives that contender a second chance to clear
// before the client gives up and reports failure.
var (
	clientBusyRetries = 3
	clientBusyBackoff = 400 * time.Millisecond
	clientSleep       = time.Sleep
)

// timeNow is time.Now, named so the deadline arithmetic in server.go and
// client.go reads symmetrically.
var timeNow = time.Now

// Client is a signer.Signer that forwards PublicKeyDER and Sign to a running
// signet agent over its Unix socket.
type Client struct {
	socket  string
	timeout time.Duration
}

// NewClient returns a Client for the agent socket at path.
func NewClient(socket string) *Client {
	return &Client{socket: socket, timeout: dialTimeout}
}

// Enrol via the agent does NOT generate a key (the agent has no such op);
// it returns the slot's existing public key, the way `signet enrol` reports a
// key it did not need to create. Key generation stays a host operation.
func (c *Client) Enrol(userPresence bool) (string, error) {
	return c.PublicKeyDER()
}

func (c *Client) PublicKeyDER() (string, error) {
	resp, err := c.callWithBusyRetry(request{Op: "pubkey"})
	if err != nil {
		return "", err
	}
	if resp.PublicKeyDER == "" {
		return "", fmt.Errorf("signet agent: empty public key in response")
	}
	return resp.PublicKeyDER, nil
}

func (c *Client) Sign(message string) (string, error) {
	resp, err := c.callWithBusyRetry(request{Op: "sign", Message: message})
	if err != nil {
		return "", err
	}
	if resp.SignatureB64 == "" {
		return "", fmt.Errorf("signet agent: empty signature in response")
	}
	return resp.SignatureB64, nil
}

// callWithBusyRetry retries the whole round trip while the agent reports the
// card busy (signer.IsCardBusy), and returns immediately on success or any
// other failure — a dial error, "no key enrolled", a broker-unrelated fault —
// none of which a retry can fix.
func (c *Client) callWithBusyRetry(req request) (response, error) {
	var resp response
	var err error
	for attempt := 0; ; attempt++ {
		resp, err = c.call(req)
		if err == nil || attempt >= clientBusyRetries || !signer.IsCardBusy(err) {
			return resp, err
		}
		clientSleep(clientBusyBackoff)
	}
}

func (c *Client) call(req request) (response, error) {
	conn, err := net.DialTimeout("unix", c.socket, c.timeout)
	if err != nil {
		return response{}, fmt.Errorf("signet agent: dial %s: %w", c.socket, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(timeNow().Add(c.timeout))

	b, err := json.Marshal(req)
	if err != nil {
		return response{}, err
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return response{}, fmt.Errorf("signet agent: write %s: %w", c.socket, err)
	}

	var resp response
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return response{}, fmt.Errorf("signet agent: read %s: %w", c.socket, err)
	}
	if resp.Error != "" {
		return response{}, fmt.Errorf("signet agent: %s", resp.Error)
	}
	return resp, nil
}
