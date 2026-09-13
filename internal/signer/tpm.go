// tpm.go: TPM 2.0 backend for signet.
//
// Uses the google/go-tpm tpm2 package (pure Go). Two key models, selected by
// identity:
//
//   - The default identity ("consumer", whether from --identity or its
//     absence) keeps the original behaviour unchanged: an ECDSA P-256 signing
//     key persisted at the fixed owner-hierarchy handle 0x81010001, nothing on
//     disk. This is backward-compatible with a host enrolled before named
//     identities existed.
//   - Any other --identity gets its own key, born under a deterministic
//     storage primary (tpm2.ECCSRKTemplate under the owner hierarchy —
//     CreatePrimary is deterministic given a fixed template and an unchanged
//     hierarchy seed, so it is never persisted; it is simply recreated,
//     transiently, on every use) via TPM2_Create. TPM2_Create returns the new
//     key wrapped (encrypted) under that primary, so the blob signet writes to
//     ~/.signet/tpm-<identity>.key is opaque and loadable only by re-deriving
//     the same primary on the same TPM — the on-disk file model Secure Enclave
//     already uses, generalised to a substrate with no per-identity NV
//     storage. This avoids consuming one of a real TPM's few persistent-object
//     slots per identity: a fleet host can hold as many identities as it has
//     files, exactly like Secure Enclave.
//
// In both cases the private key is only ever present inside the TPM: Create
// returns an encrypted private area the TPM alone can decrypt (via Load, under
// the matching parent), and Sign never exposes it.
//
// Device paths:
//   - Linux:   /dev/tpmrm0 (resource manager) or /dev/tpm0 (fallback)
//   - Windows: TBS (Trusted Platform Module Base Services)
//   - Other:   no device known; backend unavailable (auto-detect falls through)
package signer

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/radar-hooves/signet/internal/datadir"
)

// tpmPersistentHandle is the fixed owner-hierarchy persistent handle for the
// default identity's signing key. Range 0x81010000–0x810FFFFF is
// user-persistent.
const tpmPersistentHandle = tpm2.TPMHandle(0x81010001)

// tpmDefaultIdentity is the identity name that keeps the legacy fixed-handle
// key, whether it arrived via an omitted --identity or an explicit one — the
// same "consumer" default every backend resolves to (configuration.md
// #--identity), so a host enrolled before named identities existed is never
// broken by a later, explicit --identity consumer.
const tpmDefaultIdentity = "consumer"

// openTPM opens the platform's TPM device by delegating to the OS-specific
// tpmOpenDevice function (tpm_open_*.go). Returns nil, nil when no device is
// found; the caller treats that as "TPM unavailable".
func openTPM() (transport.TPMCloser, error) {
	return tpmOpenDevice()
}

// tpmSigner signs with a TPM 2.0 ECDSA P-256 key. identity is already
// defaulted (never ""); tag == tpmDefaultIdentity selects the legacy
// fixed-handle key, any other value a named on-disk blob (see tpm.go's
// package doc).
type tpmSigner struct {
	identity string
}

// newTPMSigner returns a signer for identity (""  becomes tpmDefaultIdentity,
// mirroring newEnclaveSigner's default handling).
func newTPMSigner(identity string) *tpmSigner {
	if identity == "" {
		identity = tpmDefaultIdentity
	}
	return &tpmSigner{identity: identity}
}

// tpmECCKeyTemplate returns the ECDSA P-256 signing key template.
func tpmECCKeyTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256},
					),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
	}
}

// tpmCreateOrLoadPersistent returns the NamedHandle and public key of the P-256
// ECDSA signing key persisted at tpmPersistentHandle. If the handle is already
// populated, ReadPublic returns the Name; otherwise CreatePrimary + EvictControl
// creates and persists the key first.
//
// The returned NamedHandle carries the TPM Name so callers can pass it directly
// to auth-requiring commands (Sign, etc.) without a separate ReadPublic call.
func tpmCreateOrLoadPersistent(t transport.TPM) (tpm2.NamedHandle, *tpm2.TPMTPublic, error) {
	// Attempt to read an existing key at the well-known persistent handle.
	rpRsp, err := tpm2.ReadPublic{
		ObjectHandle: tpmPersistentHandle,
	}.Execute(t)
	if err == nil {
		pub, err := rpRsp.OutPublic.Contents()
		if err != nil {
			return tpm2.NamedHandle{}, nil, fmt.Errorf("TPM: decode persistent key: %w", err)
		}
		return tpm2.NamedHandle{Handle: tpmPersistentHandle, Name: rpRsp.Name}, pub, nil
	}

	// Not present — create a primary under the Owner hierarchy.
	cpRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpmECCKeyTemplate()),
	}.Execute(t)
	if err != nil {
		return tpm2.NamedHandle{}, nil, fmt.Errorf("TPM: CreatePrimary: %w", err)
	}
	transientHandle := cpRsp.ObjectHandle
	// Always flush the transient context, whether we succeed or fail below.
	defer func() { _, _ = tpm2.FlushContext{FlushHandle: transientHandle}.Execute(t) }()

	// Persist it at the well-known handle. EvictControl requires a NamedHandle
	// (the TPM needs the Name digest to authorise the eviction).
	_, err = tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: &tpm2.NamedHandle{
			Handle: transientHandle,
			Name:   cpRsp.Name,
		},
		PersistentHandle: tpmPersistentHandle,
	}.Execute(t)
	if err != nil {
		return tpm2.NamedHandle{}, nil, fmt.Errorf("TPM: EvictControl (persist key): %w", err)
	}

	// Now read back to get the persistent handle's canonical Name.
	rpRsp2, err := tpm2.ReadPublic{ObjectHandle: tpmPersistentHandle}.Execute(t)
	if err != nil {
		return tpm2.NamedHandle{}, nil, fmt.Errorf("TPM: ReadPublic after persist: %w", err)
	}
	pub, err := rpRsp2.OutPublic.Contents()
	if err != nil {
		return tpm2.NamedHandle{}, nil, fmt.Errorf("TPM: decode persisted key: %w", err)
	}
	return tpm2.NamedHandle{Handle: tpmPersistentHandle, Name: rpRsp2.Name}, pub, nil
}

// tpmPublicToSPKI converts a TPMTPublic ECC key to base64-encoded SPKI DER.
func tpmPublicToSPKI(pub *tpm2.TPMTPublic) (string, error) {
	eccParms, err := pub.Parameters.ECCDetail()
	if err != nil {
		return "", fmt.Errorf("TPM: extract ECC parameters: %w", err)
	}
	eccPoint, err := pub.Unique.ECC()
	if err != nil {
		return "", fmt.Errorf("TPM: extract ECC point: %w", err)
	}
	ecPub, err := tpm2.ECDSAPub(eccParms, eccPoint)
	if err != nil {
		return "", fmt.Errorf("TPM: build ecdsa.PublicKey: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(ecPub)
	if err != nil {
		return "", fmt.Errorf("TPM: marshal SPKI: %w", err)
	}
	return base64.StdEncoding.EncodeToString(spki), nil
}

func (s *tpmSigner) Enrol(_ bool) (string, error) {
	t, err := openTPM()
	if err != nil {
		return "", fmt.Errorf("TPM: open device: %w", err)
	}
	if t == nil {
		return "", fmt.Errorf("TPM: no TPM device found")
	}
	defer t.Close()

	if s.identity == tpmDefaultIdentity {
		_, pub, err := tpmCreateOrLoadPersistent(t)
		if err != nil {
			return "", err
		}
		return tpmPublicToSPKI(pub)
	}
	return s.enrolNamed(t)
}

// PublicKeyDER returns the enrolled public key as base64-encoded SPKI DER
// without generating a new key. Returns an error when no TPM device is found,
// when the default identity's persistent handle holds no key, or when a named
// identity has no blob file yet.
func (s *tpmSigner) PublicKeyDER() (string, error) {
	t, err := openTPM()
	if err != nil {
		return "", fmt.Errorf("TPM: open device: %w", err)
	}
	if t == nil {
		return "", fmt.Errorf("TPM: no TPM device found")
	}
	defer t.Close()

	if s.identity == tpmDefaultIdentity {
		_, pub, err := tpmCreateOrLoadPersistent(t)
		if err != nil {
			return "", err
		}
		return tpmPublicToSPKI(pub)
	}
	_, pub, cleanup, err := s.loadNamed(t)
	if err != nil {
		return "", err
	}
	defer cleanup()
	return tpmPublicToSPKI(pub)
}

func (s *tpmSigner) Sign(message string) (string, error) {
	t, err := openTPM()
	if err != nil {
		return "", fmt.Errorf("TPM: open device: %w", err)
	}
	if t == nil {
		return "", fmt.Errorf("TPM: no TPM device found")
	}
	defer t.Close()

	var namedHandle tpm2.NamedHandle
	if s.identity == tpmDefaultIdentity {
		namedHandle, _, err = tpmCreateOrLoadPersistent(t)
		if err != nil {
			return "", err
		}
	} else {
		var cleanup func()
		namedHandle, _, cleanup, err = s.loadNamed(t)
		if err != nil {
			return "", err
		}
		defer cleanup()
	}
	return tpmSignWithHandle(t, namedHandle, message)
}

// tpmSignWithHandle signs message's SHA-256 digest with the loaded key at
// namedHandle and returns the broker's base64 P1363 r||s encoding. Shared by
// the default identity's persistent handle and a named identity's freshly
// loaded transient handle — signing itself does not depend on which.
func tpmSignWithHandle(t transport.TPM, namedHandle tpm2.NamedHandle, message string) (string, error) {
	digest := sha256.Sum256([]byte(message))

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
	}.Execute(t)
	if err != nil {
		return "", fmt.Errorf("TPM: Sign: %w", err)
	}

	ecdsaSig, err := sigRsp.Signature.Signature.ECDSA()
	if err != nil {
		return "", fmt.Errorf("TPM: extract ECDSA signature: %w", err)
	}

	r := new(big.Int).SetBytes(ecdsaSig.SignatureR.Buffer)
	sv := new(big.Int).SetBytes(ecdsaSig.SignatureS.Buffer)
	p1363, err := rsToP1363(r, sv)
	if err != nil {
		return "", fmt.Errorf("TPM: %w", err)
	}
	return base64.StdEncoding.EncodeToString(p1363), nil
}

// --- named-identity key blob: TPM2_Create under a deterministic storage
// primary, wrapped private+public material on disk, TPM2_Load to use. ---

// tpmBlobPath returns the path to the named identity's key-blob file under
// signet's data directory (~/.signet), mirroring the Secure Enclave
// convention (se-<identity>.key) with a tpm- prefix.
func tpmBlobPath(identity string) (string, error) {
	base, err := datadir.Path()
	if err != nil {
		return "", fmt.Errorf("TPM: %w", err)
	}
	return filepath.Join(base, "tpm-"+safeFilename(identity)+".key"), nil
}

// tpmStoragePrimary creates the deterministic ECC storage primary that parents
// every named identity's key. tpm2.ECCSRKTemplate is the TCG reference
// template with an all-zero Unique field, so CreatePrimary reproduces the
// bit-identical key (and Name) every time it is called against the same TPM's
// owner hierarchy — there is nothing to persist. The caller must flush the
// returned transient handle.
func tpmStoragePrimary(t transport.TPM) (tpm2.NamedHandle, error) {
	cpRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(t)
	if err != nil {
		return tpm2.NamedHandle{}, fmt.Errorf("TPM: CreatePrimary (identity storage parent): %w", err)
	}
	return tpm2.NamedHandle{Handle: cpRsp.ObjectHandle, Name: cpRsp.Name}, nil
}

// encodeTPMBlob serialises a TPM2_Create response's wrapped private and
// public areas into signet's own length-prefixed on-disk format. Both TPM2B
// values are self-delimiting on the wire, but framing them ourselves keeps
// decodeTPMBlob independent of that internal detail.
func encodeTPMBlob(priv tpm2.TPM2BPrivate, pub tpm2.TPM2BPublic) []byte {
	privBytes := tpm2.Marshal(&priv)
	pubBytes := tpm2.Marshal(&pub)
	out := make([]byte, 0, 8+len(privBytes)+len(pubBytes))
	out = binary.BigEndian.AppendUint32(out, uint32(len(privBytes)))
	out = append(out, privBytes...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(pubBytes)))
	out = append(out, pubBytes...)
	return out
}

// decodeTPMBlob reverses encodeTPMBlob.
func decodeTPMBlob(data []byte) (tpm2.TPM2BPrivate, tpm2.TPM2BPublic, error) {
	priv, pubBytes, err := tpmTakeChunk(data)
	if err != nil {
		return tpm2.TPM2BPrivate{}, tpm2.TPM2BPublic{}, fmt.Errorf("TPM: decode key blob (private): %w", err)
	}
	pub, rest, err := tpmTakeChunk(pubBytes)
	if err != nil {
		return tpm2.TPM2BPrivate{}, tpm2.TPM2BPublic{}, fmt.Errorf("TPM: decode key blob (public): %w", err)
	}
	if len(rest) != 0 {
		return tpm2.TPM2BPrivate{}, tpm2.TPM2BPublic{}, fmt.Errorf("TPM: decode key blob: %d trailing byte(s)", len(rest))
	}

	privVal, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](priv)
	if err != nil {
		return tpm2.TPM2BPrivate{}, tpm2.TPM2BPublic{}, fmt.Errorf("TPM: unmarshal private area: %w", err)
	}
	pubVal, err := tpm2.Unmarshal[tpm2.TPM2BPublic](pub)
	if err != nil {
		return tpm2.TPM2BPrivate{}, tpm2.TPM2BPublic{}, fmt.Errorf("TPM: unmarshal public area: %w", err)
	}
	return *privVal, *pubVal, nil
}

// tpmTakeChunk reads one uint32-length-prefixed chunk off the front of data,
// returning the chunk and the remaining bytes.
func tpmTakeChunk(data []byte) (chunk, rest []byte, err error) {
	if len(data) < 4 {
		return nil, nil, fmt.Errorf("truncated length prefix")
	}
	n := binary.BigEndian.Uint32(data[:4])
	data = data[4:]
	if uint64(len(data)) < uint64(n) {
		return nil, nil, fmt.Errorf("truncated chunk: want %d byte(s), have %d", n, len(data))
	}
	return data[:n], data[n:], nil
}

// enrolNamed is Enrol's named-identity path: idempotent and non-destructive,
// exactly like the Secure Enclave and PIV backends — an existing blob is
// loaded and its public key returned rather than a new key being created.
func (s *tpmSigner) enrolNamed(t transport.TPM) (string, error) {
	path, err := tpmBlobPath(s.identity)
	if err != nil {
		return "", err
	}

	if data, err := os.ReadFile(path); err == nil {
		priv, pub, err := decodeTPMBlob(data)
		if err != nil {
			return "", fmt.Errorf("TPM: read existing identity %q (%s): %w", s.identity, path, err)
		}
		_, pubT, cleanup, err := tpmLoad(t, priv, pub)
		if err != nil {
			return "", err
		}
		defer cleanup()
		return tpmPublicToSPKI(pubT)
	}

	parent, err := tpmStoragePrimary(t)
	if err != nil {
		return "", err
	}
	defer func() { _, _ = tpm2.FlushContext{FlushHandle: parent.Handle}.Execute(t) }()

	createRsp, err := tpm2.Create{
		ParentHandle: parent,
		InPublic:     tpm2.New2B(tpmECCKeyTemplate()),
	}.Execute(t)
	if err != nil {
		return "", fmt.Errorf("TPM: Create (identity %q): %w", s.identity, err)
	}

	if err := writeKeyBlob(path, encodeTPMBlob(createRsp.OutPrivate, createRsp.OutPublic)); err != nil {
		return "", fmt.Errorf("TPM: write identity %q blob: %w", s.identity, err)
	}

	pub, err := createRsp.OutPublic.Contents()
	if err != nil {
		return "", fmt.Errorf("TPM: decode created public area: %w", err)
	}
	return tpmPublicToSPKI(pub)
}

// loadNamed reads the named identity's blob file and loads it into the TPM,
// returning the loaded handle, its public area, and a cleanup func the caller
// must defer to flush both the loaded object and its storage parent. Returns
// an error — never creates a key — if no blob file exists yet: enrolment
// stays a deliberate, separate act, exactly like the Secure Enclave and PIV
// backends.
func (s *tpmSigner) loadNamed(t transport.TPM) (tpm2.NamedHandle, *tpm2.TPMTPublic, func(), error) {
	path, err := tpmBlobPath(s.identity)
	if err != nil {
		return tpm2.NamedHandle{}, nil, nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return tpm2.NamedHandle{}, nil, nil, fmt.Errorf(
			"TPM: no enrolled key for identity %q (%s); run 'signet enrol --identity %s' first", s.identity, path, s.identity)
	}
	priv, pub, err := decodeTPMBlob(data)
	if err != nil {
		return tpm2.NamedHandle{}, nil, nil, fmt.Errorf("TPM: read identity %q (%s): %w", s.identity, path, err)
	}
	return tpmLoad(t, priv, pub)
}

// tpmLoad loads a wrapped private/public pair under a freshly (deterministically)
// derived storage primary. The returned cleanup flushes both the loaded object
// and the primary; the caller must defer it.
func tpmLoad(t transport.TPM, priv tpm2.TPM2BPrivate, pub tpm2.TPM2BPublic) (tpm2.NamedHandle, *tpm2.TPMTPublic, func(), error) {
	parent, err := tpmStoragePrimary(t)
	if err != nil {
		return tpm2.NamedHandle{}, nil, nil, err
	}

	loadRsp, err := tpm2.Load{
		ParentHandle: parent,
		InPrivate:    priv,
		InPublic:     pub,
	}.Execute(t)
	if err != nil {
		_, _ = tpm2.FlushContext{FlushHandle: parent.Handle}.Execute(t)
		return tpm2.NamedHandle{}, nil, nil, fmt.Errorf("TPM: Load: %w", err)
	}

	pubT, err := pub.Contents()
	if err != nil {
		_, _ = tpm2.FlushContext{FlushHandle: loadRsp.ObjectHandle}.Execute(t)
		_, _ = tpm2.FlushContext{FlushHandle: parent.Handle}.Execute(t)
		return tpm2.NamedHandle{}, nil, nil, fmt.Errorf("TPM: decode loaded public area: %w", err)
	}

	cleanup := func() {
		_, _ = tpm2.FlushContext{FlushHandle: loadRsp.ObjectHandle}.Execute(t)
		_, _ = tpm2.FlushContext{FlushHandle: parent.Handle}.Execute(t)
	}
	return tpm2.NamedHandle{Handle: loadRsp.ObjectHandle, Name: loadRsp.Name}, pubT, cleanup, nil
}
