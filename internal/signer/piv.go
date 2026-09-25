// piv.go: YubiKey PIV backend for signet.
//
// Uses github.com/go-piv/piv-go/v2/piv (cgo, requires PC/SC). Operates on a
// configurable PIV slot (--slot; default 9c, Digital Signature) with
// an EC P-256 key. Selecting a different slot per identity lets ONE YubiKey
// root MULTIPLE distinct signet identities: the broker resolves each identity
// by its public key, and one key per slot is one public key is one identity.
//
// Enrol: generates a new key if the slot is empty, or reads the existing public
// key otherwise. Key generation is gated by the card's management key: the
// factory default is tried first (a card still on defaults just works), and a
// rotated card whose management key is held on-card under PIN protection falls
// back to prompting for the PIN at an interactive terminal to retrieve it
// (generateEnrolKey). Signing never touches the management key.
//
// Sign: SHA-256 digests the message, calls the slot's crypto.Signer, and
// converts the DER output to the broker's P1363 r||s wire format.
package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/term"
)

// pivSigner signs with the first detected YubiKey using the PIV application,
// on the slot selected at construction from the --slot flag.
type pivSigner struct {
	slot  piv.Slot
	label string // human label for the slot, used only in error messages
}

// newPIVSigner resolves the PIV slot name and returns a signer.
func newPIVSigner(slot string) (*pivSigner, error) {
	s, label, err := pivSlot(slot)
	if err != nil {
		return nil, err
	}
	return &pivSigner{slot: s, label: label}, nil
}

// pivSlot maps a slot name to a PIV slot. Empty defaults to 9c (Digital
// Signature). Accepts the four named PIV slots (9a, 9c, 9d, 9e) and the retired
// key-management slots 82..95 (hex) — giving one YubiKey up to ~24
// independently-enrollable slots, hence up to ~24 distinct signet identities on
// a single token (one per slot).
func pivSlot(slot string) (piv.Slot, string, error) {
	raw := strings.TrimSpace(slot)
	switch strings.ToLower(raw) {
	case "", "9c":
		return piv.SlotSignature, "9c", nil
	case "9a":
		return piv.SlotAuthentication, "9a", nil
	case "9d":
		return piv.SlotKeyManagement, "9d", nil
	case "9e":
		return piv.SlotCardAuthentication, "9e", nil
	}
	// Retired key-management slots 0x82..0x95 (20 extra usable slots).
	if n, err := strconv.ParseUint(raw, 16, 32); err == nil {
		if slot, ok := piv.RetiredKeyManagementSlot(uint32(n)); ok {
			return slot, strings.ToLower(raw), nil
		}
	}
	return piv.Slot{}, "", fmt.Errorf(
		"invalid PIV slot %q (--slot); expected 9a | 9c | 9d | 9e or a retired slot 82..95 (hex)",
		raw,
	)
}

// pivCards returns the list of PC/SC smart card reader names visible to the
// OS. Used by the doctor subcommand and by openFirstYubiKey. A package var
// (not a plain func) so a test can substitute a fake reader list without a
// physical card.
var pivCards = func() ([]string, error) {
	return piv.Cards()
}

// pivOpen is piv.Open behind a seam so a test can inject a fake opener that
// simulates PC/SC contention without a physical card.
var pivOpen = piv.Open

// pivSleep is time.Sleep behind a seam so a test can drive openFirstYubiKey's
// retry loop without actually waiting.
var pivSleep = time.Sleep

// pivSharingViolation is PC/SC error 0x8010000B (SCARD_E_SHARING_VIOLATION)'s
// exact message text, verbatim from go-piv's pcscErrMsgs table. It is the
// signal that another process — this host's SSH agent (a recorded fleet
// gotcha) or a concurrent signet identity sharing the same physical YubiKey —
// holds the PC/SC-exclusive connection RIGHT NOW, not that this card, slot or
// key is unusable. go-piv's own error type wrapping this code (scErr) is
// unexported, so text is the only signal a caller outside that package has.
const pivSharingViolation = "the smart card cannot be accessed because of other connections outstanding"

// cardBusyMarker appears in the error openFirstYubiKey returns once its
// retries against pivSharingViolation are exhausted. It is matched as plain
// text (IsCardBusy), never a typed error, because it must survive a round
// trip through the agent's socket: the agent forwards a Sign/PublicKeyDER
// failure as a JSON string (internal/agent/server.go), which loses any Go
// error type, so a client-side retry can only recognise it by this text.
const cardBusyMarker = "card busy"

// pivBusyRetries and pivBusyBackoff bound how long openFirstYubiKey waits out
// another process's hold on the card before giving up. A Claude Code session
// start fans out ~85 concurrent MCP server spawns, several of which reach
// this host's SSH agent (or another signet identity) at the same instant this
// one opens the card; PC/SC's exclusive-open handshake is sub-second once the
// card is free, so six tries at 300ms (1.8s total) rides out a typical
// overlap without holding a caller for long. A caller that still cannot get
// the card gets a clearly typed, retryable error rather than the confusing
// "no key enrolled" a raw sharing violation was previously misread as.
var (
	pivBusyRetries = 6
	pivBusyBackoff = 300 * time.Millisecond
)

// IsCardBusy reports whether err is (or wraps) openFirstYubiKey's retries
// against a transient PC/SC sharing violation running out — another process
// still held the card after the whole retry window — as opposed to a genuine
// "no key enrolled" or hardware fault. A caller must not treat this the same
// as an empty slot: the fix is to try again, never to (re-)enrol.
func IsCardBusy(err error) bool {
	return err != nil && strings.Contains(err.Error(), cardBusyMarker)
}

// openFirstYubiKey opens the first YubiKey listed by piv.Cards(), retrying a
// transient PC/SC sharing violation — another process briefly holding the
// exclusive connection — rather than surfacing it as if the card or key were
// unusable. A non-transient open failure (no card present, a reader vanishing
// mid-call) is returned immediately, unretried.
func openFirstYubiKey() (*piv.YubiKey, error) {
	cards, err := pivCards()
	if err != nil {
		return nil, fmt.Errorf("PIV: list smart cards: %w", err)
	}
	if len(cards) == 0 {
		return nil, fmt.Errorf("PIV: no smart cards (YubiKeys) found")
	}

	var openErr error
	for attempt := 0; attempt <= pivBusyRetries; attempt++ {
		var yk *piv.YubiKey
		yk, openErr = pivOpen(cards[0])
		if openErr == nil {
			return yk, nil
		}
		if !strings.Contains(openErr.Error(), pivSharingViolation) {
			return nil, fmt.Errorf("PIV: open %q: %w", cards[0], openErr)
		}
		if attempt < pivBusyRetries {
			pivSleep(pivBusyBackoff)
		}
	}
	return nil, fmt.Errorf("PIV: open %q: %s (gave up after %d retries): %w",
		cards[0], cardBusyMarker, pivBusyRetries, openErr)
}

// pivPublicKey returns the existing P-256 public key in the given slot, or nil
// if the slot holds no key (or a non-EC key). It reads the KEY itself — via
// KeyInfo (firmware >= 5.3.0), falling back to the attestation certificate's
// key — and deliberately does NOT read the slot's stored X.509 certificate
// object. GenerateKey persists only the keypair and never writes a certificate,
// so a Certificate() probe always misses a freshly enrolled key: that made
// Enrol re-generate (clobbering the key) on every call, and Sign/PublicKeyDER
// report an empty slot. Errors are swallowed so the caller falls through to
// GenerateKey only when the slot is genuinely empty.
func pivPublicKey(yk *piv.YubiKey, slot piv.Slot) *ecdsa.PublicKey {
	if info, err := yk.KeyInfo(slot); err == nil {
		if pub, ok := info.PublicKey.(*ecdsa.PublicKey); ok {
			return pub
		}
	}
	// Fallback for firmware < 5.3.0 (no KeyInfo): the attestation certificate
	// carries the slot's public key. Both paths read the live key, never a
	// stored certificate, so a present key is always rediscovered.
	if cert, err := yk.Attest(slot); err == nil && cert != nil {
		if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			return pub
		}
	}
	return nil
}

func (s *pivSigner) Enrol(_ bool) (string, error) {
	yk, err := openFirstYubiKey()
	if err != nil {
		return "", err
	}
	defer yk.Close()

	// Try to read an existing key first (idempotent).
	if existing := pivPublicKey(yk, s.slot); existing != nil {
		spki, err := x509.MarshalPKIXPublicKey(existing)
		if err != nil {
			return "", fmt.Errorf("PIV: marshal existing SPKI: %w", err)
		}
		return base64.StdEncoding.EncodeToString(spki), nil
	}

	// No existing key — generate one, resolving the management key that gates
	// the write (factory default, or the card-held key retrieved with the PIN).
	pub, err := s.generateEnrolKey(yk)
	if err != nil {
		return "", err
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("PIV: generated key is not ECDSA (unexpected type %T)", pub)
	}
	spki, err := x509.MarshalPKIXPublicKey(ecPub)
	if err != nil {
		return "", fmt.Errorf("PIV: marshal SPKI: %w", err)
	}
	return base64.StdEncoding.EncodeToString(spki), nil
}

// pivKeyGen is the subset of *piv.YubiKey that enrolment's key-write path uses.
// It exists as a seam so the management-key fallback below can be exercised in a
// unit test without a physical card; *piv.YubiKey satisfies it directly.
type pivKeyGen interface {
	GenerateKey(managementKey []byte, slot piv.Slot, opts piv.Key) (crypto.PublicKey, error)
	Metadata(pin string) (*piv.Metadata, error)
}

// pivStdinIsTerminal and pivPromptPIN are the terminal seams enrolment's
// management-key fallback uses. They are package vars so a unit test can drive
// the fallback and the not-a-terminal refusal without a real TTY or card; in
// production they read the process's real stdin.
var (
	pivStdinIsTerminal = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	pivPromptPIN       = promptPINFromTerminal
)

// errEnrolNeedsTerminal is enrolment's refusal when the card's management key
// has been rotated (so the card-held key must be fetched with the PIN) but
// stdin is not an interactive terminal. It is a distinct, diagnosable error so
// an unattended run — the container case — fails fast with a clear message
// rather than blocking forever on a PIN read that will never arrive.
var errEnrolNeedsTerminal = errors.New(
	"PIV enrol: this card's management key is not the factory default, so enrolling a new key needs the PIV PIN, " +
		"which must be typed at an interactive terminal — run 'signet enrol' directly in a terminal. " +
		"The PIN is deliberately not accepted from a flag, environment variable, or file. " +
		"Signing (sign/auth/headers/verify/vend-to-file/exec) is unaffected and needs no PIN.")

// promptPINFromTerminal reads the PIV PIN from stdin with echo disabled. The
// prompt and the trailing newline go to stderr, never stdout, so the SPKI that
// enrolment prints to stdout stays the only thing on it. The PIN is returned to
// the caller alone and is never echoed, logged, or placed in an error.
func promptPINFromTerminal() (string, error) {
	fmt.Fprint(os.Stderr, "Enter PIV PIN (this card's management key is PIN-protected; the PIN is used once, only to enrol): ")
	pin, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("PIV: read PIN from terminal: %w", err)
	}
	return string(pin), nil
}

// isManagementKeyAuthError reports whether err from a default-management-key
// GenerateKey is the card refusing that key — the signal that the card has been
// rotated. A rotated YubiKey returns "security status not satisfied" (SW 0x6982)
// for a wrong management key; retry-counted or blocked variants surface as
// piv.AuthErr. Either way the default key is not this card's management key.
//
// Known gap: if the card was rotated to a management-key algorithm of a
// different length than the 24-byte default (e.g. AES-128/256), go-piv rejects
// the default key with a plain "invalid management key length" error before any
// auth exchange — not caught here, so it surfaces raw instead of triggering the
// PIN fallback. The household's chosen shape is AES-192, whose key is also 24
// bytes, so the default attempt reaches the real auth exchange and fails with
// 0x6982 as expected; the gap only bites a card rotated with an explicit
// non-default algorithm, which is outside the two supported cases.
func isManagementKeyAuthError(err error) bool {
	var authErr piv.AuthErr
	if errors.As(err, &authErr) {
		return true
	}
	var sw interface{ Status() uint16 }
	if errors.As(err, &sw) && sw.Status() == 0x6982 {
		return true
	}
	return false
}

// generateEnrolKey writes a new EC P-256 key into the slot, resolving the
// management key that gates the write. It tries the factory-default key first —
// the case for a card still on defaults, which MUST keep working so this change
// can land before the estate's card is rotated. If the default key is refused,
// the card has been rotated and its management key is now held on-card under PIN
// protection (`ykman piv access change-management-key --protect`): it prompts
// for the PIN at the terminal, retrieves the card-held key with Metadata(pin),
// and retries. Exactly two cases are supported — factory default, and
// PIN-protected-on-card — deliberately: a management key supplied out-of-band
// would be a second standing credential, which is the thing this avoids.
func (s *pivSigner) generateEnrolKey(yk pivKeyGen) (crypto.PublicKey, error) {
	opts := piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyNever,
		TouchPolicy: piv.TouchPolicyNever,
	}

	pub, err := yk.GenerateKey(piv.DefaultManagementKey, s.slot, opts)
	if err == nil {
		return pub, nil
	}
	if !isManagementKeyAuthError(err) {
		return nil, fmt.Errorf("PIV: GenerateKey (slot %s): %w", s.label, err)
	}

	// The default management key was refused: the card has been rotated. The
	// card-held key is retrievable only with the PIN, typed once, here, by the
	// person enrolling — never stored. A non-terminal stdin (the unattended
	// container case) must fail fast, not block on a PIN read that never comes.
	if !pivStdinIsTerminal() {
		return nil, errEnrolNeedsTerminal
	}
	pin, err := pivPromptPIN()
	if err != nil {
		return nil, err
	}
	meta, err := yk.Metadata(pin)
	if err != nil {
		// The wrapped error carries only a retry count, never the PIN.
		return nil, fmt.Errorf("PIV: retrieve card-held management key (wrong PIN, or PIN blocked): %w", err)
	}
	if meta.ManagementKey == nil {
		return nil, fmt.Errorf("PIV: slot %s: card refused the default management key and holds no PIN-protected one; "+
			"signet supports only a factory-default key or one protected on-card with "+
			"'ykman piv access change-management-key --protect'", s.label)
	}
	pub, err = yk.GenerateKey(*meta.ManagementKey, s.slot, opts)
	if err != nil {
		return nil, fmt.Errorf("PIV: GenerateKey with card-held management key (slot %s): %w", s.label, err)
	}
	return pub, nil
}

// PublicKeyDER returns the enrolled public key as base64-encoded SPKI DER
// without generating a new key. Returns an error when no key is enrolled in
// the configured slot.
func (s *pivSigner) PublicKeyDER() (string, error) {
	yk, err := openFirstYubiKey()
	if err != nil {
		return "", err
	}
	defer yk.Close()

	pub := pivPublicKey(yk, s.slot)
	if pub == nil {
		return "", fmt.Errorf("PIV: no key in slot %s; run 'signet enrol' first", s.label)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("PIV: marshal SPKI: %w", err)
	}
	return base64.StdEncoding.EncodeToString(spki), nil
}

func (s *pivSigner) Sign(message string) (string, error) {
	yk, err := openFirstYubiKey()
	if err != nil {
		return "", err
	}
	defer yk.Close()

	// Retrieve the existing public key to pass to PrivateKey.
	pub := pivPublicKey(yk, s.slot)
	if pub == nil {
		return "", fmt.Errorf("PIV: no key in slot %s; run 'signet enrol' first", s.label)
	}

	// Obtain the crypto.Signer backed by the YubiKey.
	priv, err := yk.PrivateKey(s.slot, pub, piv.KeyAuth{})
	if err != nil {
		return "", fmt.Errorf("PIV: get private key: %w", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return "", fmt.Errorf("PIV: private key does not implement crypto.Signer")
	}

	digest := sha256.Sum256([]byte(message))

	// The PIV ECDSA signer returns a DER-encoded SEQUENCE{r, s}.
	der, err := signer.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("PIV: sign: %w", err)
	}

	p1363, err := derToP1363(der)
	if err != nil {
		return "", fmt.Errorf("PIV: convert DER to P1363: %w", err)
	}
	return base64.StdEncoding.EncodeToString(p1363), nil
}
