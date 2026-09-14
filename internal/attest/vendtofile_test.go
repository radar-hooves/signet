// vendtofile_test.go: tests for the 'signet vend-to-file' subcommand.
// Reuses the stubSigner + httptest fake-broker harness from headers_test.go /
// verify_test.go (headersBrokerWithCredBody, addAttestHandlers,
// captureHeadersOutput); no real hardware or network required.
package attest

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVendToFile_Success_SingleFieldStatic verifies the default field
// selection for a single-field static credential: the file is written
// atomically at mode 0600, its content is exactly the field's value, and
// stdout carries only the non-secret confirmation line.
func TestVendToFile_Success_SingleFieldStatic(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"value","value":"topsecretvalue123"}]}}`)
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "dest.txt")
	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	stdout, stderr := captureHeadersOutput(t, func() {
		code, err = VendToFile(s, srv.URL, "my-cred", dest, "", 0o600, false)
	})
	if err != nil {
		t.Fatalf("VendToFile: %v", err)
	}
	if code != ExitVendToFileOK {
		t.Errorf("exit code = %d, want %d (ExitVendToFileOK)", code, ExitVendToFileOK)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty on success", stderr)
	}
	if strings.Contains(stdout, "topsecretvalue123") {
		t.Error("credential value leaked into vend-to-file stdout")
	}
	wantStdout := "wrote 17 bytes to " + dest + " (mode 0600)\n"
	if stdout != wantStdout {
		t.Errorf("stdout = %q, want %q", stdout, wantStdout)
	}

	info, statErr := os.Stat(dest)
	if statErr != nil {
		t.Fatalf("stat dest: %v", statErr)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("dest mode = %o, want 0600", perm)
	}
	content, readErr := os.ReadFile(dest)
	if readErr != nil {
		t.Fatalf("read dest: %v", readErr)
	}
	if string(content) != "topsecretvalue123" {
		t.Errorf("dest content = %q, want %q", string(content), "topsecretvalue123")
	}
}

// TestVendToFile_Success_MultiFieldStaticWithField verifies --field selects
// the correct value out of a multi-field static credential.
func TestVendToFile_Success_MultiFieldStaticWithField(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"username","value":"svc-account"},{"name":"password","value":"hunter2secret"}]}}`)
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "dest.txt")
	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := VendToFile(s, srv.URL, "my-cred", dest, "password", 0o600, false)
	if err != nil {
		t.Fatalf("VendToFile: %v", err)
	}
	if code != ExitVendToFileOK {
		t.Errorf("exit code = %d, want %d (ExitVendToFileOK)", code, ExitVendToFileOK)
	}
	content, readErr := os.ReadFile(dest)
	if readErr != nil {
		t.Fatalf("read dest: %v", readErr)
	}
	if string(content) != "hunter2secret" {
		t.Errorf("dest content = %q, want %q", string(content), "hunter2secret")
	}
}

// TestVendToFile_Success_SessionAccessToken verifies session material
// defaults to writing access_token, with --field left empty.
func TestVendToFile_Success_SessionAccessToken(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"session","access_token":"livebearer987"}}`)
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "dest.txt")
	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := VendToFile(s, srv.URL, "my-cred", dest, "", 0o600, false)
	if err != nil {
		t.Fatalf("VendToFile: %v", err)
	}
	if code != ExitVendToFileOK {
		t.Errorf("exit code = %d, want %d (ExitVendToFileOK)", code, ExitVendToFileOK)
	}
	content, readErr := os.ReadFile(dest)
	if readErr != nil {
		t.Fatalf("read dest: %v", readErr)
	}
	if string(content) != "livebearer987" {
		t.Errorf("dest content = %q, want %q", string(content), "livebearer987")
	}
}

// TestVendToFile_Success_ModeOverride verifies --mode is honoured on the
// written file.
func TestVendToFile_Success_ModeOverride(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"value","value":"v"}]}}`)
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "dest.txt")
	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := VendToFile(s, srv.URL, "my-cred", dest, "", 0o640, false)
	if err != nil {
		t.Fatalf("VendToFile: %v", err)
	}
	if code != ExitVendToFileOK {
		t.Errorf("exit code = %d, want %d (ExitVendToFileOK)", code, ExitVendToFileOK)
	}
	info, statErr := os.Stat(dest)
	if statErr != nil {
		t.Fatalf("stat dest: %v", statErr)
	}
	if perm := info.Mode().Perm(); perm != 0o640 {
		t.Errorf("dest mode = %o, want 0640", perm)
	}
}

// TestVendToFile_PrintShape_Static verifies --print-shape on static material
// prints only kind + field names, writes no file, and exits 0.
func TestVendToFile_PrintShape_Static(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"username","value":"svc-account"},{"name":"password","value":"hunter2secret"}]}}`)
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "dest.txt")
	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	stdout, stderr := captureHeadersOutput(t, func() {
		code, err = VendToFile(s, srv.URL, "my-cred", dest, "", 0o600, true)
	})
	if err != nil {
		t.Fatalf("VendToFile: %v", err)
	}
	if code != ExitVendToFileOK {
		t.Errorf("exit code = %d, want %d (ExitVendToFileOK)", code, ExitVendToFileOK)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}
	if strings.Contains(stdout, "svc-account") || strings.Contains(stdout, "hunter2secret") {
		t.Error("a field value leaked into --print-shape output")
	}
	want := "kind: static\nfields: username, password\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Errorf("--print-shape must not create dest; stat error = %v", statErr)
	}
}

// TestVendToFile_PrintShape_Session verifies --print-shape on session
// material reports the access_token field name only.
func TestVendToFile_PrintShape_Session(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"session","access_token":"livebearer987"}}`)
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "dest.txt")
	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	stdout, _ := captureHeadersOutput(t, func() {
		code, err = VendToFile(s, srv.URL, "my-cred", dest, "", 0o600, true)
	})
	if err != nil {
		t.Fatalf("VendToFile: %v", err)
	}
	if code != ExitVendToFileOK {
		t.Errorf("exit code = %d, want %d (ExitVendToFileOK)", code, ExitVendToFileOK)
	}
	want := "kind: session\nfields: access_token\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Errorf("--print-shape must not create dest; stat error = %v", statErr)
	}
}

// TestVendToFile_AmbiguousMultiFieldNoField verifies exit code 6 and an
// absent dest when a multi-field static credential is vended with no
// --field, and that the error names only field NAMES, never values.
func TestVendToFile_AmbiguousMultiFieldNoField(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"username","value":"svc-account"},{"name":"password","value":"hunter2secret"}]}}`)
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "dest.txt")
	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	_, stderr := captureHeadersOutput(t, func() {
		code, err = VendToFile(s, srv.URL, "my-cred", dest, "", 0o600, false)
	})
	if err != nil {
		t.Fatalf("VendToFile: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitVendToFileUnusableMaterial {
		t.Errorf("exit code = %d, want %d (ExitVendToFileUnusableMaterial)", code, ExitVendToFileUnusableMaterial)
	}
	if !strings.Contains(stderr, "username") || !strings.Contains(stderr, "password") {
		t.Errorf("stderr = %q, want it to name the available field names", stderr)
	}
	if strings.Contains(stderr, "svc-account") || strings.Contains(stderr, "hunter2secret") {
		t.Error("a field value leaked into the ambiguous-field error")
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Errorf("dest must not be created on failure; stat error = %v", statErr)
	}
}

// TestVendToFile_FieldNotFound verifies exit code 6 and an absent dest when
// --field names a field the static material does not have.
func TestVendToFile_FieldNotFound(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"username","value":"svc-account"}]}}`)
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "dest.txt")
	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := VendToFile(s, srv.URL, "my-cred", dest, "nonexistent", 0o600, false)
	if err != nil {
		t.Fatalf("VendToFile: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitVendToFileUnusableMaterial {
		t.Errorf("exit code = %d, want %d (ExitVendToFileUnusableMaterial)", code, ExitVendToFileUnusableMaterial)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Errorf("dest must not be created on failure; stat error = %v", statErr)
	}
}

// TestVendToFile_SessionNoAccessToken verifies exit code 6 and an absent
// dest for a cookie-only session credential (no access_token).
func TestVendToFile_SessionNoAccessToken(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"session"}}`)
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "dest.txt")
	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	_, stderr := captureHeadersOutput(t, func() {
		code, err = VendToFile(s, srv.URL, "my-cred", dest, "", 0o600, false)
	})
	if err != nil {
		t.Fatalf("VendToFile: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitVendToFileUnusableMaterial {
		t.Errorf("exit code = %d, want %d (ExitVendToFileUnusableMaterial)", code, ExitVendToFileUnusableMaterial)
	}
	if !strings.Contains(stderr, "access_token") {
		t.Errorf("stderr = %q, want it to name the access_token gap", stderr)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Errorf("dest must not be created on failure; stat error = %v", statErr)
	}
}

// TestVendToFile_CredOutOfScope verifies exit code 4 and an absent dest when
// the broker returns 403 on the credential vend endpoint.
func TestVendToFile_CredOutOfScope(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusForbidden, "")
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "dest.txt")
	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := VendToFile(s, srv.URL, "my-cred", dest, "", 0o600, false)
	if err != nil {
		t.Fatalf("VendToFile: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitVendToFileCredOutOfScope {
		t.Errorf("exit code = %d, want %d (ExitVendToFileCredOutOfScope)", code, ExitVendToFileCredOutOfScope)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Errorf("dest must not be created on failure; stat error = %v", statErr)
	}
}

// TestVendToFile_VendFailureClasses table-drives every non-2xx
// credential-vend status vend-to-file must classify distinctly, mirroring
// TestHeaders_VendFailureClasses (radar-hooves/mcp-servers#868): a locked
// vault (423) must never be reported as "not found in catalogue", and dest
// must stay absent on every one of these failures.
func TestVendToFile_VendFailureClasses(t *testing.T) {
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
			wantCode:   ExitVendToFileCredNotFound,
			wantStderr: []string{`credential "my-cred" not found in catalogue (404)`},
		},
		{
			name:         "423 locked",
			status:       http.StatusLocked,
			body:         `{"error":"locked","detail":"the vault is locked, unseal it first"}`,
			wantCode:     ExitVendToFileVaultLocked,
			wantStderr:   []string{"423", "vault is locked", "the vault is locked, unseal it first"},
			refuseStderr: []string{"not found in catalogue"},
		},
		{
			name:         "500 internal error",
			status:       http.StatusInternalServerError,
			body:         `{"error":"internal","detail":"database unreachable"}`,
			wantCode:     ExitVendToFileBrokerError,
			wantStderr:   []string{"500", "database unreachable"},
			refuseStderr: []string{"not found in catalogue", "vault is locked"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setTempHome(t)
			srv := headersBrokerWithCredBody(t, tc.status, tc.body)
			defer srv.Close()

			dest := filepath.Join(t.TempDir(), "dest.txt")
			s := &stubSigner{sig: "c3R1YnNpZw=="}
			var code int
			var err error
			stdout, stderr := captureHeadersOutput(t, func() {
				code, err = VendToFile(s, srv.URL, "my-cred", dest, "", 0o600, false)
			})
			if err != nil {
				t.Fatalf("VendToFile: unexpected non-nil error for typed exit: %v", err)
			}
			if code != tc.wantCode {
				t.Errorf("exit code = %d, want %d", code, tc.wantCode)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty on failure", stdout)
			}
			if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
				t.Errorf("dest must not be created on failure; stat error = %v", statErr)
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

// TestVendToFile_KeyMissing verifies exit code 2 when PublicKeyDER fails (key
// not enrolled). The broker must not be contacted at all, and dest must not
// be created.
func TestVendToFile_KeyMissing(t *testing.T) {
	setTempHome(t)
	dest := filepath.Join(t.TempDir(), "dest.txt")
	s := &stubSigner{pubKeyErr: errors.New("key blob not found")}
	// Use an unreachable URL; any attempt to dial it would produce a transport
	// error that would appear as exit code 1, catching a regression.
	code, err := VendToFile(s, "http://127.0.0.1:0", "my-cred", dest, "", 0o600, false)
	if err != nil {
		t.Fatalf("VendToFile: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitVendToFileKeyMissing {
		t.Errorf("exit code = %d, want %d (ExitVendToFileKeyMissing)", code, ExitVendToFileKeyMissing)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Errorf("dest must not be created on failure; stat error = %v", statErr)
	}
}

// TestVendToFile_AttestRejected verifies exit code 3 when the broker returns
// 401 on the attestation challenge, and that the shared attestRejectedHint
// wording quotes the broker's own detail and names both live causes (not
// enrolled, or the per-key pending-challenge cap) rather than asserting the
// wrong one with confidence.
func TestVendToFile_AttestRejected(t *testing.T) {
	setTempHome(t)
	srv := rejectingBroker(t, http.StatusUnauthorized)
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "dest.txt")
	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	_, stderr := captureHeadersOutput(t, func() {
		code, err = VendToFile(s, srv.URL, "my-cred", dest, "", 0o600, false)
	})
	if err != nil {
		t.Fatalf("VendToFile: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitVendToFileAttestRejected {
		t.Errorf("exit code = %d, want %d (ExitVendToFileAttestRejected)", code, ExitVendToFileAttestRejected)
	}
	if !strings.Contains(stderr, "not enrolled for this identity, or too many challenges pending for this key") {
		t.Errorf("stderr = %q, want the two-cause guidance after a broker-rejected attestation", stderr)
	}
	if !strings.Contains(stderr, "unauthenticated: attestation failed") {
		t.Errorf("stderr = %q, want the broker's own quoted detail", stderr)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Errorf("dest must not be created on failure; stat error = %v", statErr)
	}
}

// TestVendToFile_PreExistingDestUnchangedOnFailure verifies that a dest file
// which already exists before a failing call is left byte-for-byte and
// mode-for-mode unchanged — proving the atomic-write path never touches dest
// until the very last, all-succeeded step.
func TestVendToFile_PreExistingDestUnchangedOnFailure(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusNotFound, "")
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "dest.txt")
	const original = "pre-existing content, must not change"
	if err := os.WriteFile(dest, []byte(original), 0o644); err != nil {
		t.Fatalf("seed dest: %v", err)
	}

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := VendToFile(s, srv.URL, "my-cred", dest, "", 0o600, false)
	if err != nil {
		t.Fatalf("VendToFile: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitVendToFileCredNotFound {
		t.Errorf("exit code = %d, want %d (ExitVendToFileCredNotFound)", code, ExitVendToFileCredNotFound)
	}

	content, readErr := os.ReadFile(dest)
	if readErr != nil {
		t.Fatalf("read dest: %v", readErr)
	}
	if string(content) != original {
		t.Errorf("dest content changed on failure: got %q, want %q", string(content), original)
	}
	info, statErr := os.Stat(dest)
	if statErr != nil {
		t.Fatalf("stat dest: %v", statErr)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("dest mode changed on failure: got %o, want 0644", perm)
	}

	// No temp file should be left behind in the destination directory either.
	entries, readDirErr := os.ReadDir(filepath.Dir(dest))
	if readDirErr != nil {
		t.Fatalf("read dest dir: %v", readDirErr)
	}
	for _, e := range entries {
		if e.Name() != "dest.txt" {
			t.Errorf("stray file left behind in dest dir: %s", e.Name())
		}
	}
}

// TestVendToFile_NoSecretOnStdoutOrStderr asserts that neither the vended
// credential value nor the internally minted bearer ever appears in the
// captured stdout or stderr, across a success case and a failure case.
func TestVendToFile_NoSecretOnStdoutOrStderr(t *testing.T) {
	setTempHome(t)

	t.Run("success", func(t *testing.T) {
		srv := headersBrokerWithCredBody(t, http.StatusOK,
			`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"value","value":"SUPERSECRETVALUE"}]}}`)
		defer srv.Close()

		dest := filepath.Join(t.TempDir(), "dest.txt")
		s := &stubSigner{sig: "c3R1YnNpZw=="}
		var code int
		var err error
		stdout, stderr := captureHeadersOutput(t, func() {
			code, err = VendToFile(s, srv.URL, "my-cred", dest, "", 0o600, false)
		})
		if err != nil || code != ExitVendToFileOK {
			t.Fatalf("VendToFile = (%d, %v), want (%d, nil)", code, err, ExitVendToFileOK)
		}
		if strings.Contains(stdout, "SUPERSECRETVALUE") {
			t.Error("credential value leaked into vend-to-file stdout")
		}
		if strings.Contains(stderr, "SUPERSECRETVALUE") {
			t.Error("credential value leaked into vend-to-file stderr")
		}
		// "verify-bearer-key" is the bearer the fake /v1/attest/token mints (see
		// addAttestHandlers, shared with verify_test.go / headers_test.go).
		if strings.Contains(stdout, "verify-bearer-key") || strings.Contains(stderr, "verify-bearer-key") {
			t.Error("minted bearer leaked into vend-to-file output")
		}
	})

	t.Run("unusable material failure", func(t *testing.T) {
		// Ambiguous multi-field static with no --field: a real failure path
		// (ExitVendToFileUnusableMaterial) whose error message names the
		// available field NAMES — the values must never appear anywhere.
		srv := headersBrokerWithCredBody(t, http.StatusOK,
			`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"a","value":"SUPERSECRETA"},{"name":"b","value":"SUPERSECRETB"}]}}`)
		defer srv.Close()

		dest := filepath.Join(t.TempDir(), "dest.txt")
		s := &stubSigner{sig: "c3R1YnNpZw=="}
		var code int
		var err error
		stdout, stderr := captureHeadersOutput(t, func() {
			code, err = VendToFile(s, srv.URL, "my-cred", dest, "", 0o600, false)
		})
		if err != nil {
			t.Fatalf("VendToFile: unexpected non-nil error for typed exit: %v", err)
		}
		if code != ExitVendToFileUnusableMaterial {
			t.Errorf("exit code = %d, want %d (ExitVendToFileUnusableMaterial)", code, ExitVendToFileUnusableMaterial)
		}
		if stdout != "" {
			t.Errorf("stdout = %q, want empty on failure (no partial print)", stdout)
		}
		if strings.Contains(stdout, "SUPERSECRETA") || strings.Contains(stdout, "SUPERSECRETB") {
			t.Error("credential value leaked into vend-to-file stdout")
		}
		if strings.Contains(stderr, "SUPERSECRETA") || strings.Contains(stderr, "SUPERSECRETB") {
			t.Error("credential value leaked into vend-to-file stderr")
		}
	})
}

// TestResolveField exercises resolveField directly across every material
// shape vend-to-file must handle.
func TestResolveField(t *testing.T) {
	cases := []struct {
		name    string
		m       credentialMaterial
		field   string
		want    string
		wantErr bool
	}{
		{
			name: "static single field, no --field",
			m:    credentialMaterial{Kind: "static", Fields: []credentialField{{Name: "value", Value: "v1"}}},
			want: "v1",
		},
		{
			name:  "static multi field with matching --field",
			m:     credentialMaterial{Kind: "static", Fields: []credentialField{{Name: "a", Value: "va"}, {Name: "b", Value: "vb"}}},
			field: "b",
			want:  "vb",
		},
		{
			name:    "static multi field, no --field is ambiguous",
			m:       credentialMaterial{Kind: "static", Fields: []credentialField{{Name: "a", Value: "va"}, {Name: "b", Value: "vb"}}},
			wantErr: true,
		},
		{
			name:    "static, --field not found",
			m:       credentialMaterial{Kind: "static", Fields: []credentialField{{Name: "a", Value: "va"}}},
			field:   "missing",
			wantErr: true,
		},
		{
			name:    "static zero fields",
			m:       credentialMaterial{Kind: "static", Fields: nil},
			wantErr: true,
		},
		{
			name: "session with access_token",
			m:    credentialMaterial{Kind: "session", AccessToken: "tok"},
			want: "tok",
		},
		{
			name:    "session without access_token",
			m:       credentialMaterial{Kind: "session"},
			wantErr: true,
		},
		{
			name:    "unknown kind",
			m:       credentialMaterial{Kind: "mystery"},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveField(tc.m, tc.field)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolveField(%+v, %q) = %q, nil; want an error", tc.m, tc.field, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveField(%+v, %q): %v", tc.m, tc.field, err)
			}
			if got != tc.want {
				t.Errorf("resolveField(%+v, %q) = %q, want %q", tc.m, tc.field, got, tc.want)
			}
		})
	}
}

// TestAtomicWriteFile_CleansUpTempOnRenameFailure verifies that a rename
// failure (dest replaced by a directory it cannot overwrite) removes the
// temp file rather than leaving stray state behind.
func TestAtomicWriteFile_CleansUpTempOnRenameFailure(t *testing.T) {
	dir := t.TempDir()
	// dest is a directory, so os.Rename onto it fails.
	dest := filepath.Join(dir, "dest-is-a-dir")
	if err := os.Mkdir(dest, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	_, err := atomicWriteFile(dest, "value", 0o600)
	if err == nil {
		t.Fatal("atomicWriteFile: expected error renaming onto a directory, got nil")
	}

	entries, readDirErr := os.ReadDir(dir)
	if readDirErr != nil {
		t.Fatalf("read dir: %v", readDirErr)
	}
	if len(entries) != 1 || entries[0].Name() != "dest-is-a-dir" {
		t.Errorf("expected only the pre-existing directory left in %s, got %v", dir, entries)
	}
}

// TestVendToFile_TempFileNeverWiderThanFinalModeBeforeChmod is a regression
// test for the atomic-write security property: the temp file must sit at
// os.CreateTemp's 0600 default (never wider) for the entire window before
// the deliberate chmod to the caller's requested mode. It drives the whole
// VendToFile path with --mode 0644 (wider than 0600) and uses the
// atomicWriteBeforeChmod hook to observe the temp file's permissions at the
// one moment that matters: after write+sync+close, before chmod. A future
// refactor that widened the temp file early (e.g. by passing the final mode
// into os.CreateTemp, or by chmod-ing before the write completes) would make
// this assertion fail, even though every end-state assertion elsewhere would
// still pass.
//
// Deterministic and race-free: everything runs on the test goroutine, and
// the hook fires synchronously inside atomicWriteFile's single call.
func TestVendToFile_TempFileNeverWiderThanFinalModeBeforeChmod(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"value","value":"v"}]}}`)
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "dest.txt")

	var hookCalled bool
	var permBeforeChmod os.FileMode
	old := atomicWriteBeforeChmod
	atomicWriteBeforeChmod = func(tmpPath string) {
		hookCalled = true
		info, statErr := os.Stat(tmpPath)
		if statErr != nil {
			t.Fatalf("stat temp file before chmod: %v", statErr)
		}
		permBeforeChmod = info.Mode().Perm()
	}
	defer func() { atomicWriteBeforeChmod = old }()

	// Request a mode WIDER than 0600, so a bug that skipped the chmod step
	// (or widened the temp file early) would show up as 0644 here instead of
	// the expected 0600.
	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := VendToFile(s, srv.URL, "my-cred", dest, "", 0o644, false)
	if err != nil {
		t.Fatalf("VendToFile: %v", err)
	}
	if code != ExitVendToFileOK {
		t.Fatalf("exit code = %d, want %d (ExitVendToFileOK)", code, ExitVendToFileOK)
	}
	if !hookCalled {
		t.Fatal("atomicWriteBeforeChmod hook was not invoked")
	}
	if permBeforeChmod != 0o600 {
		t.Errorf("temp file mode before chmod = %o, want 0600 (os.CreateTemp's documented default; must never be wider before the deliberate chmod)", permBeforeChmod)
	}

	// The final dest mode must still be the caller's requested 0644 — the
	// hook observing the pre-chmod state must not have interfered with the
	// chmod itself.
	info, statErr := os.Stat(dest)
	if statErr != nil {
		t.Fatalf("stat dest: %v", statErr)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("dest mode = %o, want 0644", perm)
	}
}
