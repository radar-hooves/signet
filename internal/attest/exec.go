// exec.go: 'signet exec' — attest, vend a credential, set it as an
// environment variable on a child process, and replace the current process
// image with that child, so the value passes straight from the broker into
// the child's own environment and never touches the parent session's
// environment, a shell variable, a file, or a transcript. It composes the
// same attestation leg as Headers/VendToFile with the same credential-vend
// leg, then reuses VendToFile's resolveField widening (a single or selected
// static field, or a session's access_token) rather than reimplementing it.
//
// exec exists for stdio MCP servers and similar child processes that read a
// credential from their own environment at start-up. headers solves the
// equivalent problem for an http MCP server's headersHelper; vend-to-file
// solves it for a consumer that reads a file; neither helps a stdio server,
// which needs the value in its environment before Claude Code even spawns
// it, and Claude Code's .mcp.json has no envHelper equivalent. The
// alternative — a secret-shaped env var sitting in the parent session's own
// environment — is inherited by every child process and readable by
// anything that can read that process's environment (e.g. `printenv`),
// which is exactly the leak shape exec exists to close.
package attest

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/radar-hooves/signet/internal/signer"
)

// Typed exit codes for signet exec. The first five values match Headers' and
// VendToFile's vocabulary exactly (this command performs the same
// attest-then-vend round trip, and the same field-resolution step as
// vend-to-file); ExitExecCommandNotFound is the one code specific to exec,
// covering the "argv[0] cannot be resolved to an executable" case that
// neither sibling has to handle (they never launch a child).
const (
	// ExitExecOK is defined for symmetry with the sibling commands' const
	// blocks, but a real run never produces it: on success Exec does not
	// return at all (see the doc comment below) — the process image is gone
	// before there is anything left to return a code from.
	ExitExecOK = 0
	// ExitExecKeyMissing means no key is enrolled for this identity.
	ExitExecKeyMissing = 2
	// ExitExecAttestRejected means the broker refused the attestation (401/4xx).
	ExitExecAttestRejected = 3
	// ExitExecCredOutOfScope means the identity exists but the credential
	// is not in its vend scope (broker returned 403).
	ExitExecCredOutOfScope = 4
	// ExitExecCredNotFound means the credential name does not exist in
	// the catalogue (broker returned 404).
	ExitExecCredNotFound = 5
	// ExitExecUnusableMaterial means the vended credential cannot be
	// resolved to a single value to set: see resolveField's doc comment
	// (shared with vend-to-file) for the exhaustive case list.
	ExitExecUnusableMaterial = 6
	// ExitExecCommandNotFound means argv[0] could not be resolved to an
	// executable via exec.LookPath — the child was never launched.
	ExitExecCommandNotFound = 7
)

// Exec is the vend-and-exec entry point. It:
//  1. Confirms a key is enrolled (PublicKeyDER succeeds).
//  2. Resolves argv[0] to an executable via exec.LookPath, so a bare command
//     name (e.g. "github-mcp-server") is found on PATH the way a shell would
//     find it, rather than only a path containing a slash. This runs before
//     the broker legs so a typo'd command spends no vend and leaves no
//     speculative entry in the broker's audit log.
//  3. Resolves a bearer via the shared cache path (bearer).
//  4. Vends credName via GET /v1/credentials/{credName} with the minted bearer.
//  5. Resolves one value out of the material via resolveField (shared with
//     VendToFile — the same static/session widening applies here).
//  6. Builds the child's environment: the current process environment
//     (os.Environ()), with envVar set to the vended value, REPLACING any
//     existing entry of that name rather than appending a duplicate (see
//     buildEnv).
//  7. Replaces the current process image with argv via syscall.Exec.
//
// Step 7 is why this command exists and why it does not use os/exec's
// Command+Run the way a normal "launch a subprocess" call would:
// syscall.Exec replaces THIS process's image in place rather than forking a
// child signet then sits above as a parent. That means there is no signet
// process left holding the vended value in its own memory after this call,
// no extra PID sitting between Claude Code and the MCP server it launched,
// and stdio/signal handling passes straight through untouched — which
// matters because the child speaks the MCP stdio protocol on file
// descriptors 0 and 1, and any intermediary process would have to proxy it
// rather than simply becoming it. On success syscall.Exec never returns; the
// calling process becomes argv.
//
// Windows has no execve() equivalent: the standard library's own
// implementation of syscall.Exec there is a stub that unconditionally
// returns "not supported by windows". signet exec still builds on Windows —
// nothing in this file sits behind a build tag — but at runtime the exec
// step fails there with that error, surfaced below as an ordinary exit code
// 1. signet exec is therefore unix-only in practice today; teaching it to
// spawn-and-wait on Windows instead is a different design (a second launch
// strategy with its own testability shape) and is left for when that
// platform is actually needed.
//
// Two behavioural differences from Headers and VendToFile, both because
// stdout belongs to the child's protocol, not to signet:
//   - NOTHING is written to stdout on the success path. Headers and
//     VendToFile each print exactly one confirmation line; exec must not,
//     because the child is about to speak the MCP stdio protocol on stdout,
//     and any signet chatter ahead of it would corrupt the JSON-RPC stream.
//   - The vended value never appears in argv (it is set via the child's
//     environment only), so it is never visible to `ps` or any other
//     argv-reading tool.
//
// Every diagnostic — including every failure path — goes to stderr, and
// never carries the credential value or the minted bearer: on failure the
// message names only the failure class (key missing, broker rejection, out
// of scope, not found, the shape of the unusable material, or the command
// not being found), never a secret.
//
// It returns a typed exit code and a human-readable error for failures. A
// nil error with a non-zero code means the check was conclusive and the
// caller should exit with that code. A non-nil error with exit code 1 is an
// unexpected transport, encoding, or exec failure. Returning at all — of any
// kind — means the child was never launched.
func Exec(s signer.Signer, brokerURL, credName, envVar, field string, argv []string) (exitCode int, err error) {
	// Step 1: confirm a key is enrolled.
	_, keyErr := s.PublicKeyDER()
	if keyErr != nil {
		fmt.Fprintf(os.Stderr, "signet exec: no key enrolled: %v\n", keyErr)
		return ExitExecKeyMissing, nil
	}

	// Step 2: resolve argv[0] the way a shell would — PATH lookup for a bare
	// command name, or the path used as-is when it already contains a slash.
	//
	// Deliberately BEFORE the broker legs: this is the only failure that is
	// local, free and deterministic, so checking it first means a typo'd command
	// costs no attestation, no credential vend, and no entry in the broker's
	// per-consumer audit log for a launch that was never going to happen. The
	// audit log is a security record; keeping speculative reads out of it is
	// worth more than the ordering is worth as a convenience.
	argv0, lookErr := exec.LookPath(argv[0])
	if lookErr != nil {
		fmt.Fprintf(os.Stderr, "signet exec: command %q not found: %v\n", argv[0], lookErr)
		return ExitExecCommandNotFound, nil
	}

	// Step 3: a live bearer — cached where one is healthy, attested where not.
	bc, attestErr := bearer(s, brokerURL)
	if attestErr != nil {
		// Distinguish a broker rejection (a non-2xx HTTP response, carried as a
		// *BrokerError anywhere in the wrap chain) from a transport error.
		var be *BrokerError
		if errors.As(attestErr, &be) {
			fmt.Fprintf(os.Stderr, "signet exec: broker rejected attestation: %v\n", attestErr)
			fmt.Fprintf(os.Stderr, "signet exec: %s\n", attestRejectedHint())
			return ExitExecAttestRejected, nil
		}
		fmt.Fprintf(os.Stderr, "signet exec: unexpected error: %v\n", attestErr)
		return 1, attestErr
	}

	// Step 3: vend the credential.
	endpoint := strings.TrimRight(brokerURL, "/") + "/v1/credentials/" + url.PathEscape(credName)
	status, body, getErr := vendCredential(s, brokerURL, endpoint, bc)
	if getErr != nil {
		fmt.Fprintf(os.Stderr, "signet exec: network error: %v\n", getErr)
		return 1, getErr
	}
	switch {
	case status == http.StatusForbidden:
		fmt.Fprintf(os.Stderr, "signet exec: credential %q out of scope for this identity (403)\n", credName)
		return ExitExecCredOutOfScope, nil
	case status == http.StatusNotFound:
		fmt.Fprintf(os.Stderr, "signet exec: credential %q not found in catalogue (404)\n", credName)
		return ExitExecCredNotFound, nil
	case status < 200 || status >= 300:
		fmt.Fprintf(os.Stderr, "signet exec: unexpected broker %d vending credential %q\n", status, credName)
		return 1, fmt.Errorf("unexpected broker %d on credential vend", status)
	}

	// Step 4: parse the envelope and resolve one value out of it.
	var env credentialEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		fmt.Fprintf(os.Stderr, "signet exec: credential %q: unusable material (envelope did not parse)\n", credName)
		return ExitExecUnusableMaterial, nil
	}
	value, resolveErr := resolveField(env.Material, field)
	if resolveErr != nil {
		fmt.Fprintf(os.Stderr, "signet exec: credential %q: %v\n", credName, resolveErr)
		return ExitExecUnusableMaterial, nil
	}

	// Step 6: build the child's environment.
	childEnv := buildEnv(os.Environ(), envVar, value)

	// Step 7: replace this process with argv. Does not return on success.
	execErr := syscall.Exec(argv0, argv, childEnv)
	fmt.Fprintf(os.Stderr, "signet exec: exec %q: %v\n", argv0, execErr)
	return 1, execErr
}

// buildEnv returns environ with name=value set, replacing any existing entry
// named name rather than appending a second one. Appending a duplicate
// key=value entry to an environment slice is undefined behaviour across libc
// implementations — some honour the first occurrence, some the last — so any
// existing entry for name is dropped before the new one is appended, leaving
// exactly one entry for name in the result.
func buildEnv(environ []string, name, value string) []string {
	prefix := name + "="
	out := make([]string, 0, len(environ)+1)
	for _, e := range environ {
		if strings.HasPrefix(e, prefix) {
			continue
		}
		out = append(out, e)
	}
	return append(out, prefix+value)
}
