// headers_test.go: tests for the 'signet headers' vend-to-headers helper.
// Mirrors verify_test.go's fake-broker pattern; no real hardware or network required.
package attest

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// headersBrokerWithCredBody builds a fake broker that serves the attestation
// endpoints plus GET /v1/credentials/{name} returning credStatus with body.
func headersBrokerWithCredBody(t *testing.T, credStatus int, body string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	addAttestHandlers(t, mux)
	mux.HandleFunc("/v1/credentials/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(credStatus)
		if body != "" {
			w.Write([]byte(body)) //nolint:errcheck
		}
	})
	return httptest.NewServer(mux)
}

// captureHeadersOutput runs f with both os.Stdout and os.Stderr redirected to
// pipes and returns everything written to each. Headers writes its result via
// fmt.Println (stdout) and every diagnostic via fmt.Fprintf(os.Stderr, ...),
// so this is the only way to assert on both channels.
func captureHeadersOutput(t *testing.T, f func()) (stdout, stderr string) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe (stdout): %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe (stderr): %v", err)
	}
	os.Stdout = outW
	os.Stderr = errW
	f()
	outW.Close()
	errW.Close()
	os.Stdout = oldOut
	os.Stderr = oldErr
	outBytes, err := io.ReadAll(outR)
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	errBytes, err := io.ReadAll(errR)
	if err != nil {
		t.Fatalf("read captured stderr: %v", err)
	}
	return string(outBytes), string(errBytes)
}

// TestHeaders_Success verifies exit code 0, the exact compact-JSON stdout
// line (default header "Authorization", default format "bearer"), and a
// silent stderr.
func TestHeaders_Success(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"value","value":"topsecretvalue123"}]}}`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	stdout, stderr := captureHeadersOutput(t, func() {
		code, err = Headers(s, srv.URL, "my-cred", "Authorization", "bearer", false)
	})
	if err != nil {
		t.Fatalf("Headers: %v", err)
	}
	if code != ExitHeadersOK {
		t.Errorf("exit code = %d, want %d (ExitHeadersOK)", code, ExitHeadersOK)
	}
	want := `{"Authorization":"Bearer topsecretvalue123"}` + "\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty on success", stderr)
	}
}

// TestHeaders_HeaderOverride verifies --header renames the emitted JSON key.
func TestHeaders_HeaderOverride(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"value","value":"apikeyvalue"}]}}`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	stdout, _ := captureHeadersOutput(t, func() {
		code, err = Headers(s, srv.URL, "my-cred", "X-Api-Key", "bearer", false)
	})
	if err != nil {
		t.Fatalf("Headers: %v", err)
	}
	if code != ExitHeadersOK {
		t.Errorf("exit code = %d, want %d (ExitHeadersOK)", code, ExitHeadersOK)
	}
	want := `{"X-Api-Key":"Bearer apikeyvalue"}` + "\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

// TestHeaders_FormatRaw verifies --format raw omits the "Bearer " prefix.
func TestHeaders_FormatRaw(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"value","value":"rawvalue123"}]}}`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	stdout, _ := captureHeadersOutput(t, func() {
		code, err = Headers(s, srv.URL, "my-cred", "Authorization", "raw", false)
	})
	if err != nil {
		t.Fatalf("Headers: %v", err)
	}
	if code != ExitHeadersOK {
		t.Errorf("exit code = %d, want %d (ExitHeadersOK)", code, ExitHeadersOK)
	}
	want := `{"Authorization":"rawvalue123"}` + "\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

// TestHeaders_Bare verifies the bare framing emits exactly the header value
// ("Bearer <value>" under the default format) with no JSON framing and no
// trailing decoration beyond the single newline, so that
// `v=$(signet headers --bare)` captures precisely the header value.
func TestHeaders_Bare(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"value","value":"topsecretvalue123"}]}}`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	stdout, stderr := captureHeadersOutput(t, func() {
		code, err = Headers(s, srv.URL, "my-cred", "Authorization", "bearer", true)
	})
	if err != nil {
		t.Fatalf("Headers: %v", err)
	}
	if code != ExitHeadersOK {
		t.Errorf("exit code = %d, want %d (ExitHeadersOK)", code, ExitHeadersOK)
	}
	// The whole contract in one assertion: exact value, exactly one trailing
	// newline, nothing else.
	want := "Bearer topsecretvalue123\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	// Assert the absence of JSON framing explicitly. The equality above already
	// implies it, but naming it is the point of the mode: a caller interpolating
	// this into `curl -H` must never receive a brace, a quote, or the header
	// name. A failure here says exactly which trap reopened.
	for _, frame := range []string{"{", "}", `"`, "Authorization", ":"} {
		if strings.Contains(stdout, frame) {
			t.Errorf("bare stdout %q contains JSON framing %q; must be the value alone", stdout, frame)
		}
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty on success", stderr)
	}
}

// TestHeaders_BareRaw verifies bare framing composes with --format raw to emit
// the bare token alone — no "Bearer " prefix and no JSON framing. This is the
// shape a caller interpolates into `curl -H "Authorization: Bearer $v"`.
func TestHeaders_BareRaw(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"value","value":"rawvalue123"}]}}`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	stdout, _ := captureHeadersOutput(t, func() {
		code, err = Headers(s, srv.URL, "my-cred", "Authorization", "raw", true)
	})
	if err != nil {
		t.Fatalf("Headers: %v", err)
	}
	if code != ExitHeadersOK {
		t.Errorf("exit code = %d, want %d (ExitHeadersOK)", code, ExitHeadersOK)
	}
	want := "rawvalue123\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if strings.Contains(stdout, "Bearer") {
		t.Errorf("stdout = %q, want no \"Bearer \" prefix under format raw", stdout)
	}
}

// TestHeaders_BareIgnoresHeaderName verifies the bare framing never prints the
// header name, whatever it is. The CLI refuses --header with --bare (see
// TestRunHeaders_BareWithHeaderRefused); this pins the library behaviour that
// refusal rests on, so a caller reaching Headers directly cannot get a name
// smuggled into a value it is about to interpolate.
func TestHeaders_BareIgnoresHeaderName(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"value","value":"apikeyvalue"}]}}`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	stdout, _ := captureHeadersOutput(t, func() {
		code, err = Headers(s, srv.URL, "my-cred", "X-Api-Key", "raw", true)
	})
	if err != nil {
		t.Fatalf("Headers: %v", err)
	}
	if code != ExitHeadersOK {
		t.Errorf("exit code = %d, want %d (ExitHeadersOK)", code, ExitHeadersOK)
	}
	want := "apikeyvalue\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q (header name must not appear)", stdout, want)
	}
}

// TestHeaders_BareNoPartialPrintOnFailure verifies the bare framing keeps
// headers' no-partial-print contract: an unusable credential prints nothing to
// stdout, so a caller substituting the output into a shell variable gets an
// empty string rather than a diagnostic fragment.
func TestHeaders_BareNoPartialPrintOnFailure(t *testing.T) {
	setTempHome(t)
	// Multi-field static, not a session: session material became usable on
	// 2026-08-13, so it no longer exercises the failure path this test is about.
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"a","value":"SUPERSECRETSESSIONVALUE"},{"name":"b","value":"SUPERSECRETSESSIONVALUE2"}]}}`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	stdout, stderr := captureHeadersOutput(t, func() {
		code, _ = Headers(s, srv.URL, "my-cred", "Authorization", "bearer", true)
	})
	if code != ExitHeadersUnusableMaterial {
		t.Errorf("exit code = %d, want %d (ExitHeadersUnusableMaterial)", code, ExitHeadersUnusableMaterial)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty on failure (no partial print)", stdout)
	}
	if strings.Contains(stderr, "SUPERSECRETSESSIONVALUE") {
		t.Error("credential value leaked into headers stderr under --bare")
	}
}

// TestHeaders_BareRefusesControlChars verifies --bare refuses a value carrying
// a CR, LF, or NUL instead of printing it. Bare is the only unescaped output
// path and exists to be interpolated into a header unquoted, so an embedded
// CRLF is a header-injection vector and an embedded newline would break the
// one-line contract --bare advertises. None may appear in an HTTP field value
// (RFC 9110), so the material is unusable for this mode.
//
// The refusal must not echo the value: the diagnostic names the control
// character only.
func TestHeaders_BareRefusesControlChars(t *testing.T) {
	cases := []struct {
		name    string
		value   string // as embedded in the broker's JSON body
		wantMsg string
	}{
		{"newline", `good\nX-Injected: evil`, "a newline"},
		{"carriage return", `good\r\nX-Injected: evil`, "a carriage return"},
		{"nul", `good\u0000evil`, "a NUL byte"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setTempHome(t)
			srv := headersBrokerWithCredBody(t, http.StatusOK,
				`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"value","value":"`+tc.value+`"}]}}`)
			defer srv.Close()

			s := &stubSigner{sig: "c3R1YnNpZw=="}
			var code int
			stdout, stderr := captureHeadersOutput(t, func() {
				code, _ = Headers(s, srv.URL, "my-cred", "Authorization", "raw", true)
			})
			if code != ExitHeadersUnusableMaterial {
				t.Errorf("exit code = %d, want %d (ExitHeadersUnusableMaterial)", code, ExitHeadersUnusableMaterial)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty: the value must never be printed unescaped", stdout)
			}
			if !strings.Contains(stderr, tc.wantMsg) {
				t.Errorf("stderr = %q, want it to name %q", stderr, tc.wantMsg)
			}
			if strings.Contains(stderr, "evil") {
				t.Errorf("stderr = %q, leaked part of the credential value", stderr)
			}
		})
	}
}

// TestHeaders_JSONAllowsControlChars pins the other half: the DEFAULT JSON
// framing still accepts such a value, escaping it so the output stays one line.
// That path is the pre-existing headersHelper contract and #5 requires it stay
// wire-compatible, so the --bare guard must not leak into it. Asserting this
// keeps the guard's scope honest rather than silently widening a refusal.
func TestHeaders_JSONAllowsControlChars(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"value","value":"good\nvalue"}]}}`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	stdout, _ := captureHeadersOutput(t, func() {
		code, _ = Headers(s, srv.URL, "my-cred", "Authorization", "raw", false)
	})
	if code != ExitHeadersOK {
		t.Errorf("exit code = %d, want %d (the JSON path is unchanged)", code, ExitHeadersOK)
	}
	// json.Marshal escapes the newline, so the emitted line stays one line.
	want := `{"Authorization":"good\nvalue"}` + "\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if strings.Count(stdout, "\n") != 1 {
		t.Errorf("stdout = %q, want exactly one physical newline (the terminator)", stdout)
	}
}

// TestHeaders_SessionAccessToken verifies a `session` credential carrying an
// access_token emits the header, exactly as a single static field does. This
// is the `produced` class — an OAuth bearer the broker mints and renews — and
// it was refused here until 2026-08-13 while vend-to-file already accepted it,
// which made the whole class unreachable over a headersHelper.
func TestHeaders_SessionAccessToken(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"session","access_token":"livebearer"}}`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	stdout, stderr := captureHeadersOutput(t, func() {
		code, err = Headers(s, srv.URL, "my-cred", "Authorization", "bearer", false)
	})
	if err != nil {
		t.Fatalf("Headers: %v", err)
	}
	if code != ExitHeadersOK {
		t.Errorf("exit code = %d, want %d (ExitHeadersOK)", code, ExitHeadersOK)
	}
	want := `{"Authorization":"Bearer livebearer"}` + "\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty on success", stderr)
	}
}

// TestHeaders_SessionWithoutAccessTokenRefused verifies exit code 6 for a
// cookie-only session: a normal, expected shape that carries no bearer, so
// there is nothing to put in a header and guessing at a cookie is not the job.
func TestHeaders_SessionWithoutAccessTokenRefused(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"session","cookies":[{"name":"sid","value":"SECRETCOOKIE"}]}}`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	stdout, stderr := captureHeadersOutput(t, func() {
		code, err = Headers(s, srv.URL, "my-cred", "Authorization", "bearer", false)
	})
	if err != nil {
		t.Fatalf("Headers: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitHeadersUnusableMaterial {
		t.Errorf("exit code = %d, want %d (ExitHeadersUnusableMaterial)", code, ExitHeadersUnusableMaterial)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty on failure", stdout)
	}
	if strings.Contains(stderr, "SECRETCOOKIE") {
		t.Errorf("stderr leaked a credential value: %q", stderr)
	}
}

// TestHeaders_MultiFieldRefused verifies exit code 6 when static material
// carries more than one field (headers cannot pick one on the caller's behalf).
func TestHeaders_MultiFieldRefused(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"a","value":"SECRETA"},{"name":"b","value":"SECRETB"}]}}`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := Headers(s, srv.URL, "my-cred", "Authorization", "bearer", false)
	if err != nil {
		t.Fatalf("Headers: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitHeadersUnusableMaterial {
		t.Errorf("exit code = %d, want %d (ExitHeadersUnusableMaterial)", code, ExitHeadersUnusableMaterial)
	}
}

// TestHeaders_ZeroFieldsRefused verifies exit code 6 when static material
// carries zero fields.
func TestHeaders_ZeroFieldsRefused(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[]}}`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := Headers(s, srv.URL, "my-cred", "Authorization", "bearer", false)
	if err != nil {
		t.Fatalf("Headers: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitHeadersUnusableMaterial {
		t.Errorf("exit code = %d, want %d (ExitHeadersUnusableMaterial)", code, ExitHeadersUnusableMaterial)
	}
}

// TestHeaders_UnparsableEnvelope verifies exit code 6 when the broker's 200
// body is not valid JSON.
func TestHeaders_UnparsableEnvelope(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusOK, `not json`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := Headers(s, srv.URL, "my-cred", "Authorization", "bearer", false)
	if err != nil {
		t.Fatalf("Headers: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitHeadersUnusableMaterial {
		t.Errorf("exit code = %d, want %d (ExitHeadersUnusableMaterial)", code, ExitHeadersUnusableMaterial)
	}
}

// TestHeaders_CredOutOfScope verifies exit code 4 when the broker returns 403
// on the credential vend endpoint.
func TestHeaders_CredOutOfScope(t *testing.T) {
	setTempHome(t)
	srv := headersBrokerWithCredBody(t, http.StatusForbidden, "")
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := Headers(s, srv.URL, "my-cred", "Authorization", "bearer", false)
	if err != nil {
		t.Fatalf("Headers: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitHeadersCredOutOfScope {
		t.Errorf("exit code = %d, want %d (ExitHeadersCredOutOfScope)", code, ExitHeadersCredOutOfScope)
	}
}

// TestHeaders_VendFailureClasses table-drives every non-2xx credential-vend
// status headers must classify distinctly, pinned against
// radar-hooves/mcp-servers#868: a locked vault (423) was read through the
// 404 branch and printed "credential %q not found in catalogue (404)",
// sending the reader hunting a catalogue the broker had never even
// consulted — verify, hitting the same locked broker, correctly reported
// "unexpected broker 423".
func TestHeaders_VendFailureClasses(t *testing.T) {
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
			wantCode:   ExitHeadersCredNotFound,
			wantStderr: []string{`credential "my-cred" not found in catalogue (404)`},
		},
		{
			name:         "423 locked",
			status:       http.StatusLocked,
			body:         `{"error":"locked","detail":"the vault is locked, unseal it first"}`,
			wantCode:     ExitHeadersVaultLocked,
			wantStderr:   []string{"423", "vault is locked", "the vault is locked, unseal it first"},
			refuseStderr: []string{"not found in catalogue"},
		},
		{
			name:         "500 internal error",
			status:       http.StatusInternalServerError,
			body:         `{"error":"internal","detail":"database unreachable"}`,
			wantCode:     ExitHeadersBrokerError,
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
				code, err = Headers(s, srv.URL, "my-cred", "Authorization", "bearer", false)
			})
			if err != nil {
				t.Fatalf("Headers: unexpected non-nil error for typed exit: %v", err)
			}
			if code != tc.wantCode {
				t.Errorf("exit code = %d, want %d", code, tc.wantCode)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty on failure", stdout)
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

// TestHeaders_KeyMissing verifies exit code 2 when PublicKeyDER fails (key
// not enrolled). The broker must not be contacted at all.
func TestHeaders_KeyMissing(t *testing.T) {
	setTempHome(t)
	s := &stubSigner{pubKeyErr: errors.New("key blob not found")}
	// Use an unreachable URL; any attempt to dial it would produce a transport
	// error that would appear as exit code 1, catching a regression.
	code, err := Headers(s, "http://127.0.0.1:0", "my-cred", "Authorization", "bearer", false)
	if err != nil {
		t.Fatalf("Headers: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitHeadersKeyMissing {
		t.Errorf("exit code = %d, want %d (ExitHeadersKeyMissing)", code, ExitHeadersKeyMissing)
	}
}

// TestHeaders_AttestRejected verifies exit code 3 when the broker returns 401
// on the attestation challenge (resolves to a broker-rejection, not transport),
// and that the guidance line steers the reader local: headers is the path every
// headersHelper consumer runs, and a bare "broker 401" here sent readers off
// diagnosing the broker when the usual cause is the default identity's key not
// being enrolled (the estate finding; verify had the wording, headers did not).
func TestHeaders_AttestRejected(t *testing.T) {
	setTempHome(t)
	srv := rejectingBroker(t, http.StatusUnauthorized)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	_, stderr := captureHeadersOutput(t, func() {
		code, err = Headers(s, srv.URL, "my-cred", "Authorization", "bearer", false)
	})
	if err != nil {
		t.Fatalf("Headers: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitHeadersAttestRejected {
		t.Errorf("exit code = %d, want %d (ExitHeadersAttestRejected)", code, ExitHeadersAttestRejected)
	}
	if !strings.Contains(stderr, "local, not an outage") {
		t.Errorf("stderr = %q, want the local-not-an-outage guidance after a broker-rejected attestation", stderr)
	}
}

// TestHeaders_NoSecretInStderr asserts that neither the vended credential
// value nor the internally minted bearer ever appears on stderr. headers
// deliberately prints the credential value to STDOUT (that is its entire
// purpose), but every diagnostic and failure path must stay silent about it.
func TestHeaders_NoSecretInStderr(t *testing.T) {
	setTempHome(t)
	// Multi-field static, not a session: session material became usable on
	// 2026-08-13, so it no longer reaches the diagnostic path under test.
	srv := headersBrokerWithCredBody(t, http.StatusOK,
		`{"name":"my-cred","material":{"kind":"static","fields":[{"name":"a","value":"SUPERSECRETSESSIONVALUE"},{"name":"b","value":"SUPERSECRETSESSIONVALUE2"}]}}`)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	stdout, stderr := captureHeadersOutput(t, func() {
		code, err = Headers(s, srv.URL, "my-cred", "Authorization", "bearer", false)
	})
	if err != nil {
		t.Fatalf("Headers: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitHeadersUnusableMaterial {
		t.Errorf("exit code = %d, want %d (ExitHeadersUnusableMaterial)", code, ExitHeadersUnusableMaterial)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty on failure (no partial print)", stdout)
	}
	if strings.Contains(stderr, "SUPERSECRETSESSIONVALUE") {
		t.Error("credential value leaked into headers stderr")
	}
	// "verify-bearer-key" is the bearer the fake /v1/attest/token mints (see
	// addAttestHandlers, shared with verify_test.go) — used only as the
	// Authorization header when calling the broker; it must never appear in
	// headers' own output.
	if strings.Contains(stderr, "verify-bearer-key") {
		t.Error("minted bearer leaked into headers stderr")
	}
}
