// vendfailure_test.go: unit tests for the classification headers, exec, and
// vend-to-file share (vendfailure.go). Integration-level coverage of each
// command's own stderr wording and exit code lives in that command's own
// _test.go (TestHeaders_VendFailureClasses, TestExec_VendFailureClasses,
// TestVendToFile_VendFailureClasses).
package attest

import (
	"net/http"
	"testing"
)

// TestClassifyVend table-drives every status the shared classifier must
// place into a distinct outcome, pinned against radar-hooves/mcp-servers#868:
// a 423 (locked vault) was previously read as unclassified and fell into
// whichever branch happened to run next.
func TestClassifyVend(t *testing.T) {
	cases := []struct {
		status int
		want   vendOutcome
	}{
		{http.StatusForbidden, vendOutOfScope},
		{http.StatusNotFound, vendNotFound},
		{http.StatusLocked, vendLocked},
		{http.StatusBadRequest, vendOtherError},
		{http.StatusInternalServerError, vendOtherError},
		{http.StatusBadGateway, vendOtherError},
		{http.StatusTooManyRequests, vendOtherError},
	}
	for _, tc := range cases {
		if got := classifyVend(tc.status); got != tc.want {
			t.Errorf("classifyVend(%d) = %v, want %v", tc.status, got, tc.want)
		}
	}
}

// TestVendBrokerDetail verifies the broker-detail formatting: both fields,
// detail only, error only, and a body that is not the {error, detail} shape
// at all (falls back to the raw, trimmed body).
func TestVendBrokerDetail(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "error and detail",
			body: `{"error":"locked","detail":"the vault is locked, unseal it first"}`,
			want: "locked: the vault is locked, unseal it first",
		},
		{
			name: "detail only",
			body: `{"detail":"database unreachable"}`,
			want: "database unreachable",
		},
		{
			name: "error only",
			body: `{"error":"internal"}`,
			want: "internal",
		},
		{
			name: "not JSON",
			body: "  upstream timed out  ",
			want: "upstream timed out",
		},
		{
			name: "JSON but not the error/detail shape",
			body: `{"name":"my-cred","purpose":"login"}`,
			want: `{"name":"my-cred","purpose":"login"}`,
		},
		{
			name: "empty",
			body: "",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := vendBrokerDetail([]byte(tc.body)); got != tc.want {
				t.Errorf("vendBrokerDetail(%q) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}
