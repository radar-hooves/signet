// auth.go: the 'signet auth' credential-helper flow.
package attest

import (
	"encoding/json"
	"fmt"

	"github.com/radar-hooves/signet/internal/signer"
)

// Auth is the credential-helper entry point. It resolves a bearer through the
// shared cache path (reuse, renew near expiry, re-attest otherwise) and prints
// {"Authorization":"Bearer <key>"} to stdout.
//
// The bearer cache is keyed by broker URL and the enrolled public key's
// fingerprint (resolve-by-key).
func Auth(s signer.Signer, brokerURL string) error {
	bc, err := bearer(s, brokerURL)
	if err != nil {
		return err
	}
	printAuthHeader(bc.Key)
	return nil
}

// printAuthHeader prints the credential-helper headers contract to stdout:
// {"Authorization":"Bearer <key>"} (compact JSON, one line), the shape
// consumers ingest verbatim as HTTP headers.
func printAuthHeader(key string) {
	type authJSON struct {
		Authorization string `json:"Authorization"`
	}
	out, _ := json.Marshal(authJSON{Authorization: "Bearer " + key})
	fmt.Println(string(out))
}
