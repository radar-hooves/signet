// exec_test.go: tests for the 'signet exec' subcommand.
// Reuses the stubSigner + httptest fake-broker harness from headers_test.go /
// vendtofile_test.go (headersBrokerWithCredBody, addAttestHandlers,
// rejectingBroker, captureHeadersOutput); no real hardware or network
// required.
//
// The one line that cannot be exercised here is the successful syscall.Exec
// call itself: on success it replaces the test binary's own process image,
// which would end the test process rather than let it report a result.
// Everything up to that call — attestation, vend, field resolution, argv[0]
// lookup, and env construction — is factored out and tested directly instead
// (see buildEnv below), so the untestable surface stays exactly that one
// line.
package attest

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// TestExec_KeyMissing verifies exit code 2 when PublicKeyDER fails (key not
// enrolled). The broker must not be contacted at all.
func TestExec_KeyMissing(t *testing.T) {
	setTempHome(t)
	s := &stubSigner{pubKeyErr: errors.New("key blob not found")}
	// Use an unreachable URL; any attempt to dial it would produce a transport
	// error that would appear as exit code 1, catching a regression.
	code, err := Exec(s, "http://127.0.0.1:0", "my-cred", "MY_TOKEN", "", []string{"true"})
	if err != nil {
		t.Fatalf("Exec: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitExecKeyMissing {
		t.Errorf("exit code = %d, want %d (ExitExecKeyMissing)", code, ExitExecKeyMissing)
	}
}

// TestExec_KeyCardBusy verifies that a transient PC/SC sharing violation
// (openFirstYubiKey's retries exhausted, per internal/signer.IsCardBusy) is
// reported as "card busy", never misread as "no key enrolled".
func TestExec_KeyCardBusy(t *testing.T) {
	setTempHome(t)
	s := &stubSigner{pubKeyErr: errors.New(`PIV: open "reader": card busy (gave up after 6 retries): the smart card cannot be accessed because of other connections outstanding`)}
	code, err := Exec(s, "http://127.0.0.1:0", "my-cred", "MY_TOKEN", "", []string{"true"})
	if err == nil {
		t.Fatal("Exec: want a non-nil error for a card-busy failure (exit 1, not a typed conclusive exit)")
	}
	if code != 1 {
		t.Errorf("exit code = %d, want 1 (card busy is transient, not the typed key-missing exit)", code)
	}
}

// TestExec_AttestRejected verifies exit code 3 when the broker returns 401 on
// the attestation challenge, and that the shared attestRejectedHint wording
// quotes the broker's own detail and names both live causes (not enrolled, or
// the per-key pending-challenge cap) rather than asserting the wrong one with
// confidence.
func TestExec_AttestRejected(t *testing.T) {
	setTempHome(t)
	srv := rejectingBroker(t, http.StatusUnauthorized)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	_, stderr := captureHeadersOutput(t, func() {
		code, err = Exec(s, srv.URL, "my-cred", "MY_TOKEN", "", []string{"true"})
	})
	if err != nil {
		t.Fatalf("Exec: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitExecAttestRejected {
		t.Errorf("exit code = %d, want %d (ExitExecAttestRejected)", code, ExitExecAttestRejected)
	}
	if !strings.Contains(stderr, "not enrolled for this identity, or too many challenges pending for this key") {
		t.Errorf("stderr = %q, want the two-cause guidance after a broker-rejected attestation", stderr)
	}
	if !strings.Contains(stderr, "unauthenticated: attestation failed") {
		t.Errorf("stderr = %q, want the broker's own quoted detail", stderr)
	}
}

// TestExec_CredOutOfScope verifies exit code 4 when the broker returns 403
// on the credential vend endpoint.
func TestExec_CredOutOfScope(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusForbidden, "")
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := Exec(s, srv.URL, "my-cred", "MY_TOKEN", "", []string{"true"})
	if err != nil {
		t.Fatalf("Exec: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitExecCredOutOfScope {
		t.Errorf("exit code = %d, want %d (ExitExecCredOutOfScope)", code, ExitExecCredOutOfScope)
	}
}

// TestExec_VendFailureClasses table-drives every non-2xx credential-vend
// status exec must classify distinctly, mirroring
// TestHeaders_VendFailureClasses (radar-hooves/mcp-servers#868): a locked
// vault (423) must never be reported as "not found in catalogue".
func TestExec_VendFailureClasses(t *testing.T) {
	cases := []struct {
		name         string
		status       int
		body         string
		wantCode     int
		wantStderr   []string
		refuseStderr []string
	}{
		{
			name:       "404 not found",
			status:     http.StatusNotFound,
			wantCode:   ExitExecCredNotFound,
			wantStderr: []string{`credential "my-cred" not found in catalogue (404)`},
		},
		{
			name:         "423 locked",
			status:       http.StatusLocked,
			body:         `{"error":"locked","detail":"the vault is locked, unseal it first"}`,
			wantCode:     ExitExecVaultLocked,
			wantStderr:   []string{"423", "vault is locked", "the vault is locked, unseal it first"},
			refuseStderr: []string{"not found in catalogue"},
		},
		{
			name:         "500 internal error",
			status:       http.StatusInternalServerError,
			body:         `{"error":"internal","detail":"database unreachable"}`,
			wantCode:     ExitExecBrokerError,
			wantStderr:   []string{"500", "database unreachable"},
			refuseStderr: []string{"not found in catalogue", "vault is locked"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setTempHome(t)
			srv := headersBrokerWithCredBody(t, tc.status, tc.body)
			defer srv.Close()

			s := &stubSigner{sig: "c3R1YnNpZw=="}
			var code int
			var err error
			stdout, stderr := captureHeadersOutput(t, func() {
				code, err = Exec(s, srv.URL, "my-cred", "MY_TOKEN", "", []string{"true"})
			})
			if err != nil {
				t.Fatalf("Exec: unexpected non-nil error for typed exit: %v", err)
			}
			if code != tc.wantCode {
				t.Errorf("exit code = %d, want %d", code, tc.wantCode)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty on failure (no partial print, and stdout belongs to the child)", stdout)
			}
			for _, want := range tc.wantStderr {
				if !strings.Contains(stderr, want) {
					t.Errorf("stderr = %q, want it to contain %q", stderr, want)
				}
			}
			for _, refuse := range tc.refuseStderr {
				if strings.Contains(stderr, refuse) {
					t.Errorf("stderr = %q, must not contain %q", stderr, refuse)
				}
			}
		})
	}
}

// TestExec_UnusableMaterial verifies exit code 6 for the same material shapes
// vend-to-file refuses: an ambiguous multi-field static credential with no
// --field, and (separately) an unparsable envelope. resolveField itself is
// already exhaustively tested by TestResolveField in vendtofile_test.go; this
// just pins that Exec wires the same function in on the same failure path.
func TestExec_UnusableMaterial(t *testing.T) {
	setTempHome(t)

	t.Run("ambiguous multi-field static, no --field", func(t *testing.T) {
		srv := headersBrokerWithCredBody(t, http.StatusOK,
			`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"a","value":"SECRETA"},{"name":"b","value":"SECRETB"}]}}`)
		defer srv.Close()

		s := &stubSigner{sig: "c3R1YnNpZw=="}
		var code int
		var err error
		stdout, stderr := captureHeadersOutput(t, func() {
			code, err = Exec(s, srv.URL, "my-cred", "MY_TOKEN", "", []string{"true"})
		})
		if err != nil {
			t.Fatalf("Exec: unexpected non-nil error for typed exit: %v", err)
		}
		if code != ExitExecUnusableMaterial {
			t.Errorf("exit code = %d, want %d (ExitExecUnusableMaterial)", code, ExitExecUnusableMaterial)
		}
		if stdout != "" {
			t.Errorf("stdout = %q, want empty on failure", stdout)
		}
		if strings.Contains(stderr, "SECRETA") || strings.Contains(stderr, "SECRETB") {
			t.Error("a field value leaked into the ambiguous-field error")
		}
	})

	t.Run("unparsable envelope", func(t *testing.T) {
		srv := headersBrokerWithCredBody(t, http.StatusOK, `not json`)
		defer srv.Close()

		s := &stubSigner{sig: "c3R1YnNpZw=="}
		code, err := Exec(s, srv.URL, "my-cred", "MY_TOKEN", "", []string{"true"})
		if err != nil {
			t.Fatalf("Exec: unexpected non-nil error for typed exit: %v", err)
		}
		if code != ExitExecUnusableMaterial {
			t.Errorf("exit code = %d, want %d (ExitExecUnusableMaterial)", code, ExitExecUnusableMaterial)
		}
	})
}

// TestExec_CommandNotFound verifies exit code 7 when argv[0] cannot be
// resolved to an executable via PATH — the credential is vended successfully
// (attestation and vend both succeed) but the child is never launched, and
// the vended value must not leak into the diagnostic.
func TestExec_CommandNotFound(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"value","value":"SUPERSECRETVALUE"}]}}`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	stdout, stderr := captureHeadersOutput(t, func() {
		code, err = Exec(s, srv.URL, "my-cred", "MY_TOKEN", "", []string{"signet-exec-test-definitely-not-a-real-binary"})
	})
	if err != nil {
		t.Fatalf("Exec: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitExecCommandNotFound {
		t.Errorf("exit code = %d, want %d (ExitExecCommandNotFound)", code, ExitExecCommandNotFound)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty on failure (no partial print, and stdout belongs to the child)", stdout)
	}
	if strings.Contains(stdout, "SUPERSECRETVALUE") || strings.Contains(stderr, "SUPERSECRETVALUE") {
		t.Error("credential value leaked into exec output on a command-not-found failure")
	}
}

// TestExec_NothingOnStdoutOnSuccessPath verifies the one behavioural
// difference from headers/vend-to-file that matters most: exec must never
// write anything to stdout, even on the path that gets all the way through
// attestation, vend, and field resolution, because stdout belongs to the
// child's own protocol. It stops one step short of the actual exec (this
// drives Exec with a command that WILL be found, "true", but true is a
// real binary and calling it would replace the test process) by instead
// exercising the identical code path via a command that fails LookPath —
// covered separately in TestExec_CommandNotFound — plus the explicit
// per-failure-path stdout assertions above. This test asserts the general
// invariant directly against a failure path that gets furthest before
// bailing: unusable material, which parses the whole successful vend first.
func TestExec_NothingOnStdoutOnSuccessPath(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"session"}}`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	stdout, _ := captureHeadersOutput(t, func() {
		code, _ = Exec(s, srv.URL, "my-cred", "MY_TOKEN", "", []string{"true"})
	})
	if code != ExitExecUnusableMaterial {
		t.Errorf("exit code = %d, want %d (ExitExecUnusableMaterial)", code, ExitExecUnusableMaterial)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty — exec must never print a confirmation line, unlike headers/vend-to-file", stdout)
	}
}

// TestExec_NoSecretOnStdoutOrStderr asserts that neither the vended
// credential value nor the internally minted bearer ever appears in captured
// stdout or stderr, across every failure path Exec can reach without
// actually exec-ing (the one path this package cannot drive in-process).
func TestExec_NoSecretOnStdoutOrStderr(t *testing.T) {
	setTempHome(t)

	t.Run("unusable material", func(t *testing.T) {
		srv := headersBrokerWithCredBody(t, http.StatusOK,
			`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"a","value":"SUPERSECRETA"},{"name":"b","value":"SUPERSECRETB"}]}}`)
		defer srv.Close()

		s := &stubSigner{sig: "c3R1YnNpZw=="}
		var code int
		var err error
		stdout, stderr := captureHeadersOutput(t, func() {
			code, err = Exec(s, srv.URL, "my-cred", "MY_TOKEN", "", []string{"true"})
		})
		if err != nil {
			t.Fatalf("Exec: unexpected non-nil error for typed exit: %v", err)
		}
		if code != ExitExecUnusableMaterial {
			t.Errorf("exit code = %d, want %d (ExitExecUnusableMaterial)", code, ExitExecUnusableMaterial)
		}
		if strings.Contains(stdout, "SUPERSECRETA") || strings.Contains(stdout, "SUPERSECRETB") {
			t.Error("credential value leaked into exec stdout")
		}
		if strings.Contains(stderr, "SUPERSECRETA") || strings.Contains(stderr, "SUPERSECRETB") {
			t.Error("credential value leaked into exec stderr")
		}
	})

	t.Run("command not found", func(t *testing.T) {
		srv := headersBrokerWithCredBody(t, http.StatusOK,
			`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"value","value":"SUPERSECRETVALUE"}]}}`)
		defer srv.Close()

		s := &stubSigner{sig: "c3R1YnNpZw=="}
		var code int
		var err error
		stdout, stderr := captureHeadersOutput(t, func() {
			code, err = Exec(s, srv.URL, "my-cred", "MY_TOKEN", "", []string{"signet-exec-test-definitely-not-a-real-binary"})
		})
		if err != nil {
			t.Fatalf("Exec: unexpected non-nil error for typed exit: %v", err)
		}
		if code != ExitExecCommandNotFound {
			t.Errorf("exit code = %d, want %d (ExitExecCommandNotFound)", code, ExitExecCommandNotFound)
		}
		if strings.Contains(stdout, "SUPERSECRETVALUE") || strings.Contains(stderr, "SUPERSECRETVALUE") {
			t.Error("credential value leaked into exec output")
		}
		// "verify-bearer-key" is the bearer the fake /v1/attest/token mints (see
		// addAttestHandlers, shared with verify_test.go / headers_test.go).
		if strings.Contains(stdout, "verify-bearer-key") || strings.Contains(stderr, "verify-bearer-key") {
			t.Error("minted bearer leaked into exec output")
		}
	})
}

// TestBuildEnv exercises buildEnv directly: the env-construction logic Exec
// relies on to set the vended value in the child's environment without
// exec-ing anything, so it is fully unit-testable.
func TestBuildEnv(t *testing.T) {
	t.Run("appends when absent", func(t *testing.T) {
		got := buildEnv([]string{"PATH=/usr/bin", "HOME=/home/x"}, "MY_TOKEN", "s3cr3t")
		want := []string{"PATH=/usr/bin", "HOME=/home/x", "MY_TOKEN=s3cr3t"}
		if !equalStringSlices(got, want) {
			t.Errorf("buildEnv = %v, want %v", got, want)
		}
	})

	t.Run("replaces a pre-existing entry rather than duplicating it", func(t *testing.T) {
		got := buildEnv([]string{"PATH=/usr/bin", "MY_TOKEN=stale-value", "HOME=/home/x"}, "MY_TOKEN", "fresh-value")
		want := []string{"PATH=/usr/bin", "HOME=/home/x", "MY_TOKEN=fresh-value"}
		if !equalStringSlices(got, want) {
			t.Errorf("buildEnv = %v, want %v", got, want)
		}
		count := 0
		for _, e := range got {
			if strings.HasPrefix(e, "MY_TOKEN=") {
				count++
			}
		}
		if count != 1 {
			t.Errorf("buildEnv result has %d entries for MY_TOKEN, want exactly 1 (no duplicate key)", count)
		}
		if strings.Contains(strings.Join(got, "\n"), "stale-value") {
			t.Error("buildEnv left the stale value behind alongside the fresh one")
		}
	})

	t.Run("does not confuse a name that is a prefix of another name", func(t *testing.T) {
		// MY_TOKEN_EXTRA must survive a buildEnv call targeting MY_TOKEN: a
		// naive strings.HasPrefix(e, name) without the "=" would also match
		// "MY_TOKEN_EXTRA=...".
		got := buildEnv([]string{"MY_TOKEN_EXTRA=untouched"}, "MY_TOKEN", "fresh-value")
		want := []string{"MY_TOKEN_EXTRA=untouched", "MY_TOKEN=fresh-value"}
		if !equalStringSlices(got, want) {
			t.Errorf("buildEnv = %v, want %v", got, want)
		}
	})

	t.Run("empty environ", func(t *testing.T) {
		got := buildEnv(nil, "MY_TOKEN", "fresh-value")
		want := []string{"MY_TOKEN=fresh-value"}
		if !equalStringSlices(got, want) {
			t.Errorf("buildEnv = %v, want %v", got, want)
		}
	})
}

// equalStringSlices compares two string slices by content and order.
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
