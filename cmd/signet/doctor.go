// doctor.go: 'signet doctor' — backend availability probe.
package main

import (
	"fmt"
	"runtime"

	"github.com/radar-hooves/signet/internal/signer"
)

// backendProbe pairs a backend name with its availability probe.
type backendProbe struct {
	backend string
	probe   func() (bool, string)
}

// cmdDoctor probes each backend (or just the one named by backend, when
// non-empty) and prints a per-backend availability report. It is the first
// triage step for any hardware-identity problem.
func cmdDoctor(backend string) error {
	all := []backendProbe{
		{"secure-enclave", signer.ProbeEnclave},
		{"tpm", signer.ProbeTPM},
		{"piv", signer.ProbePIV},
	}

	probes := all
	switch backend {
	case "":
		// Probe everything.
	case "secure-enclave", "enclave", "se":
		probes = all[0:1]
	case "tpm":
		probes = all[1:2]
	case "piv":
		probes = all[2:3]
	default:
		return fmt.Errorf("unknown backend %q; expected secure-enclave | tpm | piv", backend)
	}

	fmt.Printf("signet doctor — platform: %s/%s\n\n", runtime.GOOS, runtime.GOARCH)
	for _, p := range probes {
		ok, detail := p.probe()
		status := "UNAVAILABLE"
		if ok {
			status = "OK"
		}
		fmt.Printf("  %-18s %-14s %s\n", p.backend, status, detail)
	}

	return nil
}
