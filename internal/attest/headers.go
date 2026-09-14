// headers.go: 'signet headers' — the vend-to-headers helper for Claude Code's
// .mcp.json `headersHelper` contract. It composes the same attestation leg as
// Auth with the same credential-vend leg as Verify, then extracts a single
// static field and prints it, either as one compact-JSON HTTP header line
// (the default, which is the headersHelper contract) or as a bare line.
package attest

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/radar-hooves/signet/internal/signer"
)

// Typed exit codes for signet headers. The first five values match Verify's
// vocabulary exactly (this command performs the same attest-then-vend round
// trip); ExitHeadersUnusableMaterial is the one code specific to headers,
// covering the extra "turn the material into a single header value" step
// verify never has to take. ExitHeadersVaultLocked and ExitHeadersBrokerError
// cover the credential-vend outcomes verify only reports generically (via its
// diagnostic table's default branch, exit 1): a typed exit lets a
// headersHelper caller branch on "the vault is locked" without parsing text.
const (
	// ExitHeadersOK is success: the header line was printed to stdout.
	ExitHeadersOK = 0
	// ExitHeadersKeyMissing means no key is enrolled for this identity.
	ExitHeadersKeyMissing = 2
	// ExitHeadersAttestRejected means the broker refused the attestation (401/4xx).
	ExitHeadersAttestRejected = 3
	// ExitHeadersCredOutOfScope means the identity exists but the credential is
	// not in its vend scope (broker returned 403).
	ExitHeadersCredOutOfScope = 4
	// ExitHeadersCredNotFound means the credential name does not exist in the
	// catalogue (broker returned 404).
	ExitHeadersCredNotFound = 5
	// ExitHeadersVaultLocked means the broker's vault is locked (broker
	// returned 423); catalogue membership is unknown, and this must never be
	// reported as ExitHeadersCredNotFound (radar-hooves/mcp-servers#868).
	ExitHeadersVaultLocked = 7
	// ExitHeadersBrokerError means the broker answered the vend with a
	// non-2xx status this package has no dedicated wording for (400, 500,
	// ...); the message names the status and the broker's own error/detail.
	ExitHeadersBrokerError = 8
	// ExitHeadersUnusableMaterial means the vended credential cannot become a
	// single header value: its material is not `static`, its envelope did not
	// parse, its static fields number zero or more than one, or (under --bare
	// only, the one unescaped output path) its value carries a CR, LF, or NUL,
	// which no HTTP header value may contain.
	ExitHeadersUnusableMaterial = 6
)

// controlCharName names a control character for a diagnostic, so a refusal can
// say which one was found without echoing any part of the credential value.
func controlCharName(c byte) string {
	switch c {
	case '\r':
		return "a carriage return"
	case '\n':
		return "a newline"
	case 0:
		return "a NUL byte"
	default:
		return "a control character"
	}
}

// Headers is the vend-to-headers entry point. It:
//  1. Confirms a key is enrolled (PublicKeyDER succeeds).
//  2. Resolves a bearer via the shared cache path (bearer).
//  3. Vends credName via GET /v1/credentials/{credName} with the minted bearer.
//  4. Resolves the one value the header carries — a single `static` field, or
//     a `session`'s access_token — and prints it as the ONLY line written to
//     stdout. Resolution is shared with vend-to-file and exec (resolveField),
//     so a `produced` credential (an OAuth bearer the broker mints and renews)
//     works over a headersHelper exactly as a static API key does.
//
// Two independent axes shape that line. `format` shapes the VALUE: "bearer"
// (the default) prefixes "Bearer ", "raw" leaves the value alone. `bare`
// shapes the FRAMING: false (the default) wraps the value in a compact-JSON
// object keyed by headerName, true prints the value alone. They compose:
//
//	bare=false format="bearer"  {"Authorization":"Bearer <value>"}  (default)
//	bare=false format="raw"     {"Authorization":"<value>"}
//	bare=true  format="bearer"  Bearer <value>
//	bare=true  format="raw"     <value>
//
// The JSON framings are the headersHelper contract and are load-bearing for
// existing consumers; the bare framings exist because a JSON-wrapped value
// interpolated into `curl -H "Authorization: Bearer $v"` builds a malformed
// header, which the broker rejects as a 401 indistinguishable from a stale
// credential. headerName has no meaning when bare is true (the name is not
// printed), so the caller is refused rather than silently ignored.
//
// Every diagnostic — including every failure path — goes to stderr, and never
// carries the credential value or the minted bearer: on failure the message
// names only the failure class (key missing, broker rejection, out of scope,
// not found, or the shape of the unusable material), never a secret.
//
// It returns a typed exit code and a human-readable error for failures. A nil
// error with a non-zero code means the check was conclusive and the caller
// should exit with that code. A non-nil error with exit code 1 is an
// unexpected transport or encoding failure.
func Headers(s signer.Signer, brokerURL, credName, headerName, format string, bare bool) (exitCode int, err error) {
	// Step 1: confirm a key is enrolled.
	_, keyErr := s.PublicKeyDER()
	if keyErr != nil {
		fmt.Fprintf(os.Stderr, "signet headers: no key enrolled: %v\n", keyErr)
		return ExitHeadersKeyMissing, nil
	}

	// Step 2: a live bearer — cached where one is healthy, attested where not.
	bc, attestErr := bearer(s, brokerURL)
	if attestErr != nil {
		// Distinguish a broker rejection (a non-2xx HTTP response, carried as a
		// *BrokerError anywhere in the wrap chain) from a transport error.
		var be *BrokerError
		if errors.As(attestErr, &be) {
			fmt.Fprintf(os.Stderr, "signet headers: broker rejected attestation: %v\n", attestErr)
			fmt.Fprintf(os.Stderr, "signet headers: %s\n", attestRejectedHint(be))
			return ExitHeadersAttestRejected, nil
		}
		fmt.Fprintf(os.Stderr, "signet headers: unexpected error: %v\n", attestErr)
		return 1, attestErr
	}

	// Step 3: vend the credential.
	endpoint := strings.TrimRight(brokerURL, "/") + "/v1/credentials/" + url.PathEscape(credName)
	status, body, getErr := vendCredential(s, brokerURL, endpoint, bc)
	if getErr != nil {
		fmt.Fprintf(os.Stderr, "signet headers: network error: %v\n", getErr)
		return 1, getErr
	}
	if status < 200 || status >= 300 {
		switch classifyVend(status) {
		case vendOutOfScope:
			fmt.Fprintf(os.Stderr, "signet headers: credential %q out of scope for this identity (403)\n", credName)
			return ExitHeadersCredOutOfScope, nil
		case vendNotFound:
			fmt.Fprintf(os.Stderr, "signet headers: credential %q not found in catalogue (404)\n", credName)
			return ExitHeadersCredNotFound, nil
		case vendLocked:
			fmt.Fprintf(os.Stderr, "signet headers: broker vault is locked (423): %s\n", vendBrokerDetail(body))
			return ExitHeadersVaultLocked, nil
		default:
			fmt.Fprintf(os.Stderr, "signet headers: unexpected broker %d vending credential %q: %s\n", status, credName, vendBrokerDetail(body))
			return ExitHeadersBrokerError, nil
		}
	}

	// Step 4: resolve the one value this header carries — a single static
	// field, or a session's access_token.
	//
	// Session material was refused here until 2026-08-13, while vend-to-file
	// and exec had already been widened to accept it (resolveField, whose
	// docstring names this narrower assumption). That gap made the whole
	// `produced` credential class unreachable over a headersHelper: a broker
	// that had minted a perfectly good OAuth bearer answered `unusable
	// material (kind "session", want static)`, which reads as a broken
	// credential rather than a missing feature in the caller.
	var env credentialEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		fmt.Fprintf(os.Stderr, "signet headers: credential %q: unusable material (envelope did not parse)\n", credName)
		return ExitHeadersUnusableMaterial, nil
	}
	value, resolveErr := resolveField(env.Material, "")
	if resolveErr != nil {
		// resolveField's messages name the shape and never a value.
		fmt.Fprintf(os.Stderr, "signet headers: credential %q: %v\n", credName, resolveErr)
		return ExitHeadersUnusableMaterial, nil
	}

	// Step 5: format and print — the only line written to stdout.
	headerValue := value
	if format == "bearer" {
		headerValue = "Bearer " + value
	}
	// Bare framing: the value alone, terminated by exactly one newline and
	// nothing else, so `$(signet headers --bare)` captures precisely the value
	// (command substitution strips the trailing newline).
	//
	// A value carrying CR, LF, or NUL is refused here rather than printed. Bare
	// is the one output path with no escaping — the JSON framing escapes such a
	// value and stays one line — and it exists precisely to be interpolated
	// into a header unquoted, so an embedded CRLF is a header-injection and
	// request-splitting vector, and an embedded newline would silently break
	// the one-line contract above. RFC 9110 admits none of these in a field
	// value, so such material genuinely cannot become one header value, which
	// is exactly what ExitHeadersUnusableMaterial means. The refusal names the
	// offending control character, never the value.
	if bare {
		if i := strings.IndexAny(headerValue, "\r\n\x00"); i >= 0 {
			fmt.Fprintf(os.Stderr, "signet headers: credential %q: unusable material (value contains %s, which cannot appear in an HTTP header value; --bare prints it unescaped)\n", credName, controlCharName(headerValue[i]))
			return ExitHeadersUnusableMaterial, nil
		}
		fmt.Println(headerValue)
		return ExitHeadersOK, nil
	}
	out, marshalErr := json.Marshal(map[string]string{headerName: headerValue})
	if marshalErr != nil {
		fmt.Fprintf(os.Stderr, "signet headers: encode output: %v\n", marshalErr)
		return 1, marshalErr
	}
	fmt.Println(string(out))
	return ExitHeadersOK, nil
}
