//go:build darwin

// enclave_darwin.go: Secure Enclave backend for signet on macOS.
//
// Uses CryptoKit's SecureEnclave.P256 through a small Swift shim (enclave.swift)
// compiled to a static archive and linked into this one binary via cgo. The
// Enclave returns an OPAQUE, hardware-wrapped key blob which signet stores in a
// file it owns; the keychain is never touched. That is the whole trick: keychain
// persistence of an SE key reference needs the com.apple.application-identifier
// entitlement (an Apple-team code signature) and fails on an unsigned binary with
// -34018 errSecMissingEntitlement, whereas the self-stored-blob path needs NO
// entitlement and NO code signature. The blob is bound to this Mac's Enclave and
// is useless if copied elsewhere. This is the model age-plugin-se uses.
//
// The build needs the Swift archive in place; see the Makefile (`make build`).
// Notarisation is irrelevant to Secure Enclave access (it is a Gatekeeper
// distribution gate, not a runtime keychain/SE gate).
package signer

/*
#cgo LDFLAGS: ${SRCDIR}/libsignet_se.a -framework CryptoKit -framework Foundation -framework Security

#include <stdint.h>

int signet_se_available(void);
int signet_se_create_key(int userPresence,
    uint8_t *blobOut, int blobCap, int *blobLen,
    uint8_t *pubOut, int pubCap, int *pubLen,
    char *errBuf, int errCap);
int signet_se_public_key(const uint8_t *blob, int blobLen,
    uint8_t *pubOut, int pubCap, int *pubLen,
    char *errBuf, int errCap);
int signet_se_sign(const uint8_t *blob, int blobLen,
    const uint8_t *msg, int msgLen,
    uint8_t *sigOut, int sigCap, int *sigLen,
    char *errBuf, int errCap);
*/
import "C"

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/radar-hooves/signet/internal/datadir"
)

// seDefaultTag identifies the SE signing key; it names the on-disk blob file so
// an operator can keep more than one signet identity on one Mac. The default is
// "consumer": signet's common case is a credential consumer attesting for a
// vend, so an unconfigured caller resolves to the consumer identity. An admin or
// any per-service identity is selected with an explicit --identity.
const seDefaultTag = "consumer"

// seAvailable reports whether CryptoKit sees a Secure Enclave on this Mac.
func seAvailable() bool {
	return C.signet_se_available() != 0
}

// probeEnclave is the doctor probe for the Secure Enclave backend.
func probeEnclave() (bool, string) {
	if seAvailable() {
		return true, "CryptoKit reports Secure Enclave present"
	}
	return false, "CryptoKit reports no Secure Enclave (needs Apple Silicon or T2)"
}

// enclaveSigner signs with the macOS Secure Enclave via CryptoKit (cgo). The
// hardware-wrapped key blob is stored under signet's data directory; no
// external helper binary and no code-signing entitlement are required.
type enclaveSigner struct {
	tag string
}

func newEnclaveSigner(identity string) *enclaveSigner {
	tag := identity
	if tag == "" {
		tag = seDefaultTag
	}
	return &enclaveSigner{tag: tag}
}

// blobPath returns the path to the SE key-blob file for this signer's tag,
// under signet's data directory (~/.signet). The blob is persistent,
// hardware-wrapped key material.
func (e *enclaveSigner) blobPath() (string, error) {
	base, err := datadir.Path()
	if err != nil {
		return "", fmt.Errorf("secure-enclave: %w", err)
	}
	return filepath.Join(base, "se-"+safeFilename(e.tag)+".key"), nil
}

// safeFilename reduces an arbitrary tag to a filesystem-safe component.
func safeFilename(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "default"
	}
	return string(out)
}

func (e *enclaveSigner) Enrol(userPresence bool) (string, error) {
	if !seAvailable() {
		return "", fmt.Errorf("secure-enclave: not available on this Mac (needs Apple Silicon or a T2 chip)")
	}

	path, err := e.blobPath()
	if err != nil {
		return "", err
	}

	// Idempotent and non-destructive: an existing key is never clobbered; return
	// its public key so re-enrolling the same identity is a no-op.
	if blob, err := os.ReadFile(path); err == nil {
		x963, err := sePublicKey(blob)
		if err != nil {
			return "", fmt.Errorf("secure-enclave: read existing key %s: %w", path, err)
		}
		return marshalSPKI(x963)
	}

	blob, x963, err := seCreateKey(userPresence)
	if err != nil {
		return "", err
	}
	if err := writeKeyBlob(path, blob); err != nil {
		return "", err
	}
	return marshalSPKI(x963)
}

// PublicKeyDER returns the enrolled public key as base64-encoded SPKI DER
// without generating a new key. Returns an error when no key is enrolled.
func (e *enclaveSigner) PublicKeyDER() (string, error) {
	path, err := e.blobPath()
	if err != nil {
		return "", err
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("secure-enclave: no enrolled key at %s; run 'signet enrol' first", path)
	}
	x963, err := sePublicKey(blob)
	if err != nil {
		return "", fmt.Errorf("secure-enclave: read public key from %s: %w", path, err)
	}
	return marshalSPKI(x963)
}

func (e *enclaveSigner) Sign(message string) (string, error) {
	path, err := e.blobPath()
	if err != nil {
		return "", err
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("secure-enclave: no enrolled key at %s; run 'signet enrol' first", path)
	}
	raw, err := seSign(blob, []byte(message))
	if err != nil {
		return "", err
	}
	// CryptoKit's ECDSASignature.rawRepresentation is already the 64-byte IEEE
	// P1363 r||s the broker expects.
	return base64.StdEncoding.EncodeToString(raw), nil
}

// --- cgo bridges to the Swift shim ---

func seCreateKey(userPresence bool) (blob, x963 []byte, err error) {
	blobBuf := make([]byte, 1024)
	pubBuf := make([]byte, 256)
	errBuf := make([]byte, 256)
	var blobLen, pubLen C.int
	up := C.int(0)
	if userPresence {
		up = 1
	}
	rc := C.signet_se_create_key(up,
		(*C.uint8_t)(unsafe.Pointer(&blobBuf[0])), C.int(len(blobBuf)), &blobLen,
		(*C.uint8_t)(unsafe.Pointer(&pubBuf[0])), C.int(len(pubBuf)), &pubLen,
		(*C.char)(unsafe.Pointer(&errBuf[0])), C.int(len(errBuf)))
	if rc != 0 {
		return nil, nil, fmt.Errorf("secure-enclave: %s (code %d)", cString(errBuf), int(rc))
	}
	return clone(blobBuf[:blobLen]), clone(pubBuf[:pubLen]), nil
}

func sePublicKey(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("empty key blob")
	}
	pubBuf := make([]byte, 256)
	errBuf := make([]byte, 256)
	var pubLen C.int
	rc := C.signet_se_public_key(
		(*C.uint8_t)(unsafe.Pointer(&blob[0])), C.int(len(blob)),
		(*C.uint8_t)(unsafe.Pointer(&pubBuf[0])), C.int(len(pubBuf)), &pubLen,
		(*C.char)(unsafe.Pointer(&errBuf[0])), C.int(len(errBuf)))
	if rc != 0 {
		return nil, fmt.Errorf("secure-enclave: %s (code %d)", cString(errBuf), int(rc))
	}
	return clone(pubBuf[:pubLen]), nil
}

func seSign(blob, message []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("empty key blob")
	}
	sigBuf := make([]byte, 128)
	errBuf := make([]byte, 256)
	var sigLen C.int
	var msgPtr *C.uint8_t
	if len(message) > 0 {
		msgPtr = (*C.uint8_t)(unsafe.Pointer(&message[0]))
	}
	rc := C.signet_se_sign(
		(*C.uint8_t)(unsafe.Pointer(&blob[0])), C.int(len(blob)),
		msgPtr, C.int(len(message)),
		(*C.uint8_t)(unsafe.Pointer(&sigBuf[0])), C.int(len(sigBuf)), &sigLen,
		(*C.char)(unsafe.Pointer(&errBuf[0])), C.int(len(errBuf)))
	if rc != 0 {
		return nil, fmt.Errorf("secure-enclave: %s (code %d)", cString(errBuf), int(rc))
	}
	return clone(sigBuf[:sigLen]), nil
}

// --- helpers ---

// marshalSPKI builds an SPKI DER (base64) from a 65-byte X9.63 P-256 point.
func marshalSPKI(x963 []byte) (string, error) {
	if len(x963) != p256PointLen || x963[0] != 0x04 {
		return "", fmt.Errorf("secure-enclave: unexpected public key encoding (len %d)", len(x963))
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x963[1 : 1+p256ScalarLen]),
		Y:     new(big.Int).SetBytes(x963[1+p256ScalarLen : p256PointLen]),
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("secure-enclave: marshal SPKI: %w", err)
	}
	return base64.StdEncoding.EncodeToString(spki), nil
}

// writeKeyBlob persists the wrapped key blob (0600) under a 0700 directory,
// writing to a temp file then renaming for atomicity.
func writeKeyBlob(path string, blob []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("secure-enclave: create key directory: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return fmt.Errorf("secure-enclave: write key blob: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("secure-enclave: finalise key blob: %w", err)
	}
	return nil
}

// cString reads a NUL-terminated message out of a C error buffer.
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// clone returns an independent copy so the caller's slice does not alias a reused
// scratch buffer.
func clone(b []byte) []byte {
	return append([]byte(nil), b...)
}
