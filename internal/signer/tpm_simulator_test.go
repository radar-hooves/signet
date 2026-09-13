//go:build tpmsimulator

// tpm_simulator_test.go: TPM backend tests using the go-tpm software simulator.
// Run with: go test -tags tpmsimulator ./...
//
// The go-tpm software simulator (github.com/google/go-tpm/tpm2/transport/simulator)
// has a cgo/OpenSSL dependency (ms-tpm-20-ref). The tpmsimulator build tag keeps
// that dep out of normal builds.
package signer

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

// TestTPMEnrolAndSign exercises a full enrol+sign round-trip against the
// software TPM simulator, then verifies the P1363 signature with the returned
// public key.
func TestTPMEnrolAndSign(t *testing.T) {
	// Open the simulator.
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("open TPM simulator: %v", err)
	}
	defer sim.Close()

	// --- Enrol: create the key, extract SPKI DER ---
	_, pub, err := tpmCreateOrLoadPersistent(sim)
	if err != nil {
		t.Fatalf("tpmCreateOrLoadPersistent: %v", err)
	}

	spkiB64, err := tpmPublicToSPKI(pub)
	if err != nil {
		t.Fatalf("tpmPublicToSPKI: %v", err)
	}
	spkiDER, err := base64.StdEncoding.DecodeString(spkiB64)
	if err != nil {
		t.Fatalf("decode base64 SPKI: %v", err)
	}
	anyPub, err := x509.ParsePKIXPublicKey(spkiDER)
	if err != nil {
		t.Fatalf("parse SPKI: %v", err)
	}
	ecPub, ok := anyPub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("SPKI contains %T, want *ecdsa.PublicKey", anyPub)
	}

	// --- Sign ---
	const message = "ch-00000000-0000-0000-0000-000000000001.testnonce"
	digest := sha256.Sum256([]byte(message))

	namedHandle, _, err := tpmCreateOrLoadPersistent(sim)
	if err != nil {
		t.Fatalf("reload persistent key: %v", err)
	}

	sigRsp, err := tpm2.Sign{
		KeyHandle: namedHandle,
		Digest:    tpm2.TPM2BDigest{Buffer: digest[:]},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}.Execute(sim)
	if err != nil {
		t.Fatalf("TPM Sign: %v", err)
	}

	ecdsaSig, err := sigRsp.Signature.Signature.ECDSA()
	if err != nil {
		t.Fatalf("extract ECDSA sig: %v", err)
	}

	r := new(big.Int).SetBytes(ecdsaSig.SignatureR.Buffer)
	sv := new(big.Int).SetBytes(ecdsaSig.SignatureS.Buffer)

	// Verify the raw r,s values against the extracted public key.
	if !ecdsa.Verify(ecPub, digest[:], r, sv) {
		t.Error("ecdsa.Verify failed: TPM signature does not validate against enrolled public key")
	}

	// Verify the P1363 wire encoding round-trips correctly.
	rBytes := r.Bytes()
	sBytes := sv.Bytes()
	if len(rBytes) > 32 || len(sBytes) > 32 {
		t.Fatalf("r or s > 32 bytes: %d, %d", len(rBytes), len(sBytes))
	}
	p1363 := make([]byte, 64)
	copy(p1363[32-len(rBytes):32], rBytes)
	copy(p1363[64-len(sBytes):64], sBytes)
	if len(p1363) != 64 {
		t.Errorf("P1363 is %d bytes, want 64", len(p1363))
	}

	// Verify idempotency: a second call to tpmCreateOrLoadPersistent should
	// return the same public key (key already persisted, ReadPublic path).
	_, pub2, err := tpmCreateOrLoadPersistent(sim)
	if err != nil {
		t.Fatalf("second tpmCreateOrLoadPersistent: %v", err)
	}
	spkiB64b, err := tpmPublicToSPKI(pub2)
	if err != nil {
		t.Fatalf("second tpmPublicToSPKI: %v", err)
	}
	if spkiB64 != spkiB64b {
		t.Errorf("idempotency check: SPKI changed between calls\n  first:  %s\n  second: %s",
			spkiB64, spkiB64b)
	}
}

// verifySPKISignature decodes a base64 SPKI DER public key and a base64
// P1363 r||s signature and reports whether the signature verifies over
// message under that key.
func verifySPKISignature(t *testing.T, spkiB64, message, sigB64 string) bool {
	t.Helper()
	spkiDER, err := base64.StdEncoding.DecodeString(spkiB64)
	if err != nil {
		t.Fatalf("decode SPKI base64: %v", err)
	}
	anyPub, err := x509.ParsePKIXPublicKey(spkiDER)
	if err != nil {
		t.Fatalf("parse SPKI: %v", err)
	}
	ecPub, ok := anyPub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("SPKI contains %T, want *ecdsa.PublicKey", anyPub)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decode signature base64: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("signature is %d bytes, want 64 (P1363 r||s)", len(sig))
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	digest := sha256.Sum256([]byte(message))
	return ecdsa.Verify(ecPub, digest[:], r, s)
}

// TestTPMNamedIdentities proves the fix for radar-hooves/signet#12 end to end
// against the simulator: two named identities on one (simulated) TPM enrol to
// distinct keys, each signs, and each signature verifies against its own
// public key and fails against the other's — exactly the property a second
// broker consumer on one host depends on.
func TestTPMNamedIdentities(t *testing.T) {
	// Named identities write a key blob under ~/.signet; isolate the test from
	// the real developer home (and from other tests) with a scratch one.
	t.Setenv("HOME", t.TempDir())

	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("open TPM simulator: %v", err)
	}
	defer sim.Close()

	// The go-tpm simulator does not implement openTPM's real device probing;
	// enrolNamed/loadNamed take a transport.TPM directly, so we drive them
	// against the simulator without going through tpmSigner.Enrol/Sign (which
	// call openTPM for the real hardware paths tested by doctor/probe.go).
	alice := &tpmSigner{identity: "alice"}
	bob := &tpmSigner{identity: "bob"}

	alicePub, err := alice.enrolNamed(sim)
	if err != nil {
		t.Fatalf("enrol alice: %v", err)
	}
	bobPub, err := bob.enrolNamed(sim)
	if err != nil {
		t.Fatalf("enrol bob: %v", err)
	}
	if alicePub == bobPub {
		t.Fatalf("alice and bob enrolled the same public key %q; identities are not distinct", alicePub)
	}

	// Re-enrolling is idempotent and non-destructive: it must return the same
	// key without creating a new one.
	alicePubAgain, err := alice.enrolNamed(sim)
	if err != nil {
		t.Fatalf("re-enrol alice: %v", err)
	}
	if alicePubAgain != alicePub {
		t.Errorf("re-enrolling alice changed her key\n  first:  %s\n  second: %s", alicePub, alicePubAgain)
	}

	// Sign with each identity via the loadNamed path (what Sign uses).
	signAs := func(s *tpmSigner, message string) string {
		t.Helper()
		namedHandle, _, cleanup, err := s.loadNamed(sim)
		if err != nil {
			t.Fatalf("loadNamed %s: %v", s.identity, err)
		}
		defer cleanup()
		sig, err := tpmSignWithHandle(sim, namedHandle, message)
		if err != nil {
			t.Fatalf("sign as %s: %v", s.identity, err)
		}
		return sig
	}

	const message = "ch-00000000-0000-0000-0000-000000000002.testnonce"
	aliceSig := signAs(alice, message)
	bobSig := signAs(bob, message)

	if !verifySPKISignature(t, alicePub, message, aliceSig) {
		t.Error("alice's signature does not verify against alice's own public key")
	}
	if !verifySPKISignature(t, bobPub, message, bobSig) {
		t.Error("bob's signature does not verify against bob's own public key")
	}
	if verifySPKISignature(t, alicePub, message, bobSig) {
		t.Error("bob's signature verifies against alice's public key; identities are not cryptographically distinct")
	}
	if verifySPKISignature(t, bobPub, message, aliceSig) {
		t.Error("alice's signature verifies against bob's public key; identities are not cryptographically distinct")
	}

	// A third, never-enrolled identity must be refused, never silently
	// created: enrolment is a deliberate act, exactly like Secure Enclave/PIV.
	carol := &tpmSigner{identity: "carol"}
	if _, _, _, err := carol.loadNamed(sim); err == nil {
		t.Error("loadNamed on a never-enrolled identity should error, not silently create a key")
	}
}
