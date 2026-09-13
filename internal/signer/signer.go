// Package signer holds the hardware signing backends and the Signer
// interface the rest of signet is written against.
//
// Three backends are compiled in; selection is at runtime (New's backend
// argument, or platform auto-detection when it is empty). Only the Secure
// Enclave backend is behind a darwin build tag (it links a Swift shim via
// cgo); TPM and PIV compile on every platform.
//
//   - secure-enclave: macOS Secure Enclave via CryptoKit (a small Swift shim
//     linked into the binary by cgo). Auto-selected on darwin. Works on an
//     unsigned/ad-hoc binary: the Enclave's wrapped key blob is stored in a
//     file, not the keychain, so no code-signing entitlement is required.
//
//   - tpm: TPM 2.0 via github.com/google/go-tpm (pure Go). Auto-selected on
//     Linux and Windows when a TPM resource manager device is reachable. The
//     default identity stays at the original fixed persistent handle
//     (backward-compatible with an already-enrolled host); a named --identity
//     gets its own TPM-wrapped key blob under ~/.signet, loadable only by this
//     TPM — one machine, several consumers, the way Secure Enclave already
//     works.
//
//   - piv: YubiKey PIV, cgo against PC/SC. Auto-selected as the fallback on
//     any platform when no higher-priority backend is available. The slot is
//     selectable (default 9c), so one token can root multiple identities —
//     one per slot.
package signer

import (
	"fmt"
	"runtime"
)

// Signer is a hardware-rooted signer: it can publish its public key (Enrol),
// return the public key without side effects (PublicKeyDER), and sign a
// message (Sign). All three return the broker's wire encodings.
//
//   - Enrol returns SPKI DER (base64-encoded); idempotent — an existing key is
//     never clobbered.
//   - PublicKeyDER returns the same SPKI DER without generating a new key;
//     returns an error if no key has been enrolled yet.
//   - Sign returns the IEEE P1363 r||s ECDSA-P256 signature over
//     SHA256(message) (base64-encoded).
type Signer interface {
	Enrol(userPresence bool) (string, error)
	PublicKeyDER() (string, error)
	Sign(message string) (string, error)
}

// New selects a backend from an explicit name (empty → auto-detect).
// Auto-detect order: darwin → secure-enclave; linux/windows → tpm (if device
// reachable) then piv; other → piv. slot applies to the piv backend, identity
// to secure-enclave and tpm; each is ignored by the other backends.
func New(backend, slot, identity string) (Signer, error) {
	if backend == "" {
		backend = autoDetect()
	}
	switch backend {
	case "secure-enclave", "enclave", "se":
		return newEnclaveSigner(identity), nil
	case "tpm":
		return newTPMSigner(identity), nil
	case "piv":
		return newPIVSigner(slot)
	default:
		return nil, fmt.Errorf("unknown backend %q; expected secure-enclave | tpm | piv", backend)
	}
}

// autoDetect returns the backend name for the current platform.
func autoDetect() string {
	switch runtime.GOOS {
	case "darwin":
		return "secure-enclave"
	case "linux", "windows":
		// Probe for a TPM device; fall back to PIV if none is found.
		t, err := openTPM()
		if err == nil && t != nil {
			t.Close()
			return "tpm"
		}
		return "piv"
	default:
		return "piv"
	}
}
