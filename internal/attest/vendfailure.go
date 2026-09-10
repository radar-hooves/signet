// vendfailure.go: shared classification for a non-2xx response to a
// credential vend (GET /v1/credentials/{name}), used by headers, exec, and
// vend-to-file so the three classify a broker's answer identically instead
// of in three hand-maintained copies.
//
// Before radar-hooves/mcp-servers#868, all three folded every status that
// was not 403 or 404 into a bare "unexpected broker %d" — so a locked vault
// (423) fell through that branch and printed "credential %q not found in
// catalogue (404)" from the DISTINCT 404 branch above it (a status ==
// http.StatusNotFound check with no default case guarding it), sending the
// reader hunting a catalogue the broker had never even consulted. `verify`
// never had that bug (its default branch already prints the status and the
// broker's own body for anything it has no dedicated wording for); this
// gives the other three the same shape rather than inventing a new one.
package attest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// vendOutcome classifies a non-2xx response from a credential vend into the
// shape headers, exec, and vend-to-file each report distinctly. Callers only
// invoke classifyVend for a status that is not 2xx.
type vendOutcome int

const (
	// vendOutOfScope is 403: the identity is attested but the credential is
	// not in its vend scope.
	vendOutOfScope vendOutcome = iota
	// vendNotFound is 404: the credential name is absent from the broker's
	// catalogue.
	vendNotFound
	// vendLocked is 423: the broker's vault is locked, so catalogue
	// membership is UNKNOWN — this is never a "not found" and must not read
	// as one.
	vendLocked
	// vendOtherError is any other non-2xx (400, 409, 500, 502, 503, ...): a
	// broker-side condition with no dedicated wording, reported with its raw
	// status and the broker's own error/detail fields.
	vendOtherError
)

// classifyVend maps a non-2xx HTTP status from a credential vend to its
// vendOutcome.
func classifyVend(status int) vendOutcome {
	switch status {
	case http.StatusForbidden:
		return vendOutOfScope
	case http.StatusNotFound:
		return vendNotFound
	case http.StatusLocked:
		return vendLocked
	default:
		return vendOtherError
	}
}

// brokerErrorFields is the subset of a broker JSON error body this package
// reads: {"error": "...", "detail": "..."}. Either field may be absent.
type brokerErrorFields struct {
	Error  string `json:"error"`
	Detail string `json:"detail"`
}

// vendBrokerDetail renders body's broker-supplied error/detail fields for a
// vendLocked or vendOtherError outcome, the way verify's own default branch
// already reports an unclassified status. When body does not parse as
// {error, detail}, or both fields are empty, it falls back to the trimmed
// raw body so a broker that answers with plain text is still reported.
func vendBrokerDetail(body []byte) string {
	var f brokerErrorFields
	if err := json.Unmarshal(body, &f); err == nil {
		switch {
		case f.Error != "" && f.Detail != "":
			return fmt.Sprintf("%s: %s", f.Error, f.Detail)
		case f.Detail != "":
			return f.Detail
		case f.Error != "":
			return f.Error
		}
	}
	return strings.TrimSpace(string(body))
}
