// doctor.go: 'signet doctor' — key-file availability probe.
package main

import (
	"fmt"
	"runtime"

	"github.com/radar-hooves/signet/internal/signer"
)

// cmdDoctor probes the software key at the identity/key selection and prints
// its availability. It is the first triage step for any attest problem.
func cmdDoctor(identity, key string) error {
	path := key
	if path == "" {
		p, err := signer.DefaultKeyPath(identity)
		if err != nil {
			return err
		}
		path = p
	}

	fmt.Printf("signet doctor — platform: %s/%s\n\n", runtime.GOOS, runtime.GOARCH)
	ok, detail := signer.ProbeSoftware(path)
	status := "UNAVAILABLE"
	if ok {
		status = "OK"
	}
	fmt.Printf("  %-10s %-14s %s\n", "software", status, detail)

	if !ok {
		return fmt.Errorf("no usable key")
	}
	return nil
}
