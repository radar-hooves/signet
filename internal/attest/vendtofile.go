// vendtofile.go: 'signet vend-to-file' — attest, vend a credential, and
// write ONE field's value to a destination file atomically, so a consumer
// (an agent, a script, a stack .env sink) never has the value pass through
// its own stdout, a log, or an LLM transcript. It composes the same
// attestation leg as Headers/Verify with the same credential-vend leg, then
// widens material handling beyond headers.go's single-static-field
// assumption to also cover session material.
package attest

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/radar-hooves/signet/internal/signer"
)

// Typed exit codes for signet vend-to-file. The first five values match
// Verify's and Headers' vocabulary exactly (this command performs the same
// attest-then-vend round trip); ExitVendToFileUnusableMaterial covers every
// "cannot resolve this material to one field's value" case: an envelope that
// did not parse, an ambiguous multi-field static credential with no --field,
// a --field naming a field that is not present, a session credential with no
// access_token, or any other material kind. ExitVendToFileVaultLocked and
// ExitVendToFileBrokerError match Headers' codes of the same name and number
// (7 and 8): both commands share the same const layout up to this point.
const (
	// ExitVendToFileOK is success: the file was written (or, with
	// --print-shape, the shape was printed) and the caller printed the one
	// confirmation line to stdout.
	ExitVendToFileOK = 0
	// ExitVendToFileKeyMissing means no key is enrolled for this identity.
	ExitVendToFileKeyMissing = 2
	// ExitVendToFileAttestRejected means the broker refused the attestation (401/4xx).
	ExitVendToFileAttestRejected = 3
	// ExitVendToFileCredOutOfScope means the identity exists but the credential
	// is not in its vend scope (broker returned 403).
	ExitVendToFileCredOutOfScope = 4
	// ExitVendToFileCredNotFound means the credential name does not exist in
	// the catalogue (broker returned 404).
	ExitVendToFileCredNotFound = 5
	// ExitVendToFileUnusableMaterial means the vended credential cannot be
	// resolved to a single value to write: see the const block doc above.
	ExitVendToFileUnusableMaterial = 6
	// ExitVendToFileVaultLocked means the broker's vault is locked (broker
	// returned 423); catalogue membership is unknown, and this must never be
	// reported as ExitVendToFileCredNotFound (radar-hooves/mcp-servers#868).
	ExitVendToFileVaultLocked = 7
	// ExitVendToFileBrokerError means the broker answered the vend with a
	// non-2xx status this package has no dedicated wording for (400, 500,
	// ...); the message names the status and the broker's own error/detail.
	ExitVendToFileBrokerError = 8
)

// VendToFile is the vend-to-file entry point. It:
//  1. Confirms a key is enrolled (PublicKeyDER succeeds).
//  2. Resolves a bearer via the shared cache path (bearer).
//  3. Vends credName via GET /v1/credentials/{credName} with the minted bearer.
//  4. With printShape, prints only the material's kind and field names (never
//     a value) and returns — no file is written.
//  5. Otherwise resolves one value out of the material (see resolveField) and
//     atomically writes it to dest at mode, then prints a single non-secret
//     confirmation line ("wrote <N> bytes to <dest> (mode <mode>)") as the
//     ONLY line written to stdout.
//
// Every diagnostic — including every failure path — goes to stderr, and
// never carries the credential value or the minted bearer: on failure the
// message names only the failure class (key missing, broker rejection, out
// of scope, not found, or the shape of the unusable material), never a
// secret. On any failure dest is left untouched: never created, and never
// partially written if it already existed.
//
// It returns a typed exit code and a human-readable error for failures. A nil
// error with a non-zero code means the check was conclusive and the caller
// should exit with that code. A non-nil error with exit code 1 is an
// unexpected transport, encoding, or filesystem failure.
func VendToFile(s signer.Signer, brokerURL, credName, dest, field string, mode os.FileMode, printShape bool) (exitCode int, err error) {
	// Step 1: confirm a key is enrolled.
	_, keyErr := s.PublicKeyDER()
	if keyErr != nil {
		fmt.Fprintf(os.Stderr, "signet vend-to-file: no key enrolled: %v\n", keyErr)
		return ExitVendToFileKeyMissing, nil
	}

	// Step 2: a live bearer — cached where one is healthy, attested where not.
	bc, attestErr := bearer(s, brokerURL)
	if attestErr != nil {
		// Distinguish a broker rejection (a non-2xx HTTP response, carried as a
		// *BrokerError anywhere in the wrap chain) from a transport error.
		var be *BrokerError
		if errors.As(attestErr, &be) {
			fmt.Fprintf(os.Stderr, "signet vend-to-file: broker rejected attestation: %v\n", attestErr)
			fmt.Fprintf(os.Stderr, "signet vend-to-file: %s\n", attestRejectedHint())
			return ExitVendToFileAttestRejected, nil
		}
		fmt.Fprintf(os.Stderr, "signet vend-to-file: unexpected error: %v\n", attestErr)
		return 1, attestErr
	}

	// Step 3: vend the credential.
	endpoint := strings.TrimRight(brokerURL, "/") + "/v1/credentials/" + url.PathEscape(credName)
	status, body, getErr := vendCredential(s, brokerURL, endpoint, bc)
	if getErr != nil {
		fmt.Fprintf(os.Stderr, "signet vend-to-file: network error: %v\n", getErr)
		return 1, getErr
	}
	if status < 200 || status >= 300 {
		switch classifyVend(status) {
		case vendOutOfScope:
			fmt.Fprintf(os.Stderr, "signet vend-to-file: credential %q out of scope for this identity (403)\n", credName)
			return ExitVendToFileCredOutOfScope, nil
		case vendNotFound:
			fmt.Fprintf(os.Stderr, "signet vend-to-file: credential %q not found in catalogue (404)\n", credName)
			return ExitVendToFileCredNotFound, nil
		case vendLocked:
			fmt.Fprintf(os.Stderr, "signet vend-to-file: broker vault is locked (423): %s\n", vendBrokerDetail(body))
			return ExitVendToFileVaultLocked, nil
		default:
			fmt.Fprintf(os.Stderr, "signet vend-to-file: unexpected broker %d vending credential %q: %s\n", status, credName, vendBrokerDetail(body))
			return ExitVendToFileBrokerError, nil
		}
	}

	// Step 4: parse the envelope.
	var env credentialEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		fmt.Fprintf(os.Stderr, "signet vend-to-file: credential %q: unusable material (envelope did not parse)\n", credName)
		return ExitVendToFileUnusableMaterial, nil
	}

	// Step 5: --print-shape names the kind and the field names only — never a
	// value — and writes no file.
	if printShape {
		fmt.Printf("kind: %s\n", env.Material.Kind)
		fmt.Printf("fields: %s\n", strings.Join(fieldNames(env.Material), ", "))
		return ExitVendToFileOK, nil
	}

	// Step 6: resolve which field's value to write.
	value, resolveErr := resolveField(env.Material, field)
	if resolveErr != nil {
		fmt.Fprintf(os.Stderr, "signet vend-to-file: credential %q: %v\n", credName, resolveErr)
		return ExitVendToFileUnusableMaterial, nil
	}

	// Step 7: atomic write — dest is never created or partially written on
	// any failure from here on.
	n, writeErr := atomicWriteFile(dest, value, mode)
	if writeErr != nil {
		fmt.Fprintf(os.Stderr, "signet vend-to-file: write %s: %v\n", dest, writeErr)
		return 1, writeErr
	}

	// Step 8: the only line written to stdout — a byte count, never the value.
	fmt.Printf("wrote %d bytes to %s (mode %s)\n", n, dest, modeString(mode))
	return ExitVendToFileOK, nil
}

// staticFieldNames returns the field names (never values) of static material,
// in the order the broker returned them.
func staticFieldNames(fields []credentialField) []string {
	names := make([]string, len(fields))
	for i, f := range fields {
		names[i] = f.Name
	}
	return names
}

// fieldNames returns the field names --print-shape reports for m, without
// ever touching a value: the static field names, or "access_token" alone
// when a session credential carries one.
func fieldNames(m credentialMaterial) []string {
	switch m.Kind {
	case "static":
		return staticFieldNames(m.Fields)
	case "session":
		if m.AccessToken != "" {
			return []string{"access_token"}
		}
		return nil
	default:
		return nil
	}
}

// resolveField picks the single value vend-to-file writes from m, applying
// the widening beyond headers.go's single-static-field assumption:
//   - static: the sole field's value when there is exactly one and field is
//     empty; field selects among two or more (or overrides a single field)
//     by exact name match — a name that does not exist is an error naming
//     the available field names, never a guess.
//   - session: always the access_token field; field is not consulted (a
//     cookie-only session with no access_token is an error naming the gap,
//     never a guess at which cookie to write).
//   - any other kind: unusable material.
func resolveField(m credentialMaterial, field string) (string, error) {
	switch m.Kind {
	case "static":
		if field != "" {
			for _, f := range m.Fields {
				if f.Name == field {
					return f.Value, nil
				}
			}
			return "", fmt.Errorf("unusable material (--field %q not found; available: %s)", field, strings.Join(staticFieldNames(m.Fields), ", "))
		}
		switch len(m.Fields) {
		case 0:
			return "", fmt.Errorf("unusable material (0 static fields)")
		case 1:
			return m.Fields[0].Value, nil
		default:
			return "", fmt.Errorf("unusable material (%d static fields, want --field one of: %s)", len(m.Fields), strings.Join(staticFieldNames(m.Fields), ", "))
		}
	case "session":
		if m.AccessToken == "" {
			return "", fmt.Errorf("unusable material (session has no access_token)")
		}
		return m.AccessToken, nil
	default:
		return "", fmt.Errorf("unusable material (kind %q not supported)", m.Kind)
	}
}

// modeString renders mode as a "0NNN" octal string for the confirmation line
// (e.g. os.FileMode(0o600) -> "0600").
func modeString(mode os.FileMode) string {
	return fmt.Sprintf("0%o", mode)
}

// atomicWriteBeforeChmod, when non-nil, is invoked with the temp file's path
// once it has been written, fsynced, and closed, but BEFORE the deliberate
// chmod to the caller's requested mode. It exists solely so a test can
// observe the temp file's pre-chmod permissions — proving the file is never
// wider than os.CreateTemp's documented 0600 default in the window before
// the explicit chmod runs, regardless of what mode the caller ultimately
// requested. Production code never sets it; it is nil in every real build.
var atomicWriteBeforeChmod func(tmpPath string)

// atomicWriteFile writes value to dest atomically. A temp file is created in
// dest's own directory (so the final os.Rename is an atomic same-filesystem
// replace), written, fsynced, and chmoded to mode, and only then renamed
// over dest. On any error dest is left exactly as it was — never created,
// never partially overwritten — and the temp file is removed. Returns the
// number of bytes written.
func atomicWriteFile(dest, value string, mode os.FileMode) (int, error) {
	dir := filepath.Dir(dest)
	tmp, err := os.CreateTemp(dir, ".signet-vend-to-file-*")
	if err != nil {
		return 0, fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			os.Remove(tmpPath) //nolint:errcheck
		}
	}()

	n, err := tmp.WriteString(value)
	if err != nil {
		tmp.Close() //nolint:errcheck
		return 0, fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close() //nolint:errcheck
		return 0, fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return 0, fmt.Errorf("close temp file: %w", err)
	}
	if atomicWriteBeforeChmod != nil {
		atomicWriteBeforeChmod(tmpPath)
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return 0, fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpPath, dest); err != nil {
		return 0, fmt.Errorf("rename temp file to %s: %w", dest, err)
	}
	cleanup = false
	return n, nil
}
