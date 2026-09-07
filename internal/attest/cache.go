// cache.go: the on-disk bearer cache under ~/.signet/cache/.
//
// The cache is keyed by broker URL AND the enrolled public key's fingerprint,
// so re-enrolling (a new key for the same broker) never serves a stale bearer
// minted for the old key. It holds only short-lived tokens; deleting it simply
// forces a re-attest.
package attest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/radar-hooves/signet/internal/datadir"
)

// bearerCache is the on-disk structure stored under ~/.signet/cache/.
type bearerCache struct {
	Key          string    `json:"key"`
	ExpiresAt    time.Time `json:"expires_at"`
	MaxExpiresAt time.Time `json:"max_expires_at"`
}

// sanitiseHost replaces URL structural characters with underscores to produce
// a safe filesystem filename component from a broker URL.
func sanitiseHost(brokerURL string) string {
	r := strings.NewReplacer("://", "_", "/", "_", ":", "_")
	return r.Replace(brokerURL)
}

// publicKeyFingerprint returns the first 16 hex characters of the SHA-256
// digest of the raw DER bytes encoded in spkiB64. This is the protocol-level
// fingerprint: 16 hex chars of SHA-256(SPKI DER), used by the /v1/attest
// protocol to discriminate bearer caches per enrolled key without sending the
// key identity by name. One fingerprint per enrolled key, independent of any
// broker-side identity name.
func publicKeyFingerprint(spkiB64 string) (string, error) {
	der, err := base64.StdEncoding.DecodeString(spkiB64)
	if err != nil {
		return "", fmt.Errorf("decode SPKI base64: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])[:16], nil
}

// cacheDir returns the bearer-cache directory (~/.signet/cache), creating it
// (mode 0700) if needed.
func cacheDir() (string, error) {
	base, err := datadir.Path()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "cache")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create cache directory: %w", err)
	}
	return dir, nil
}

// cachePath returns the bearer-cache file path, keyed by broker URL AND the
// public key fingerprint.
func cachePath(brokerURL, fingerprint string) (string, error) {
	dir, err := cacheDir()
	if err != nil {
		return "", err
	}
	name := sanitiseHost(brokerURL) + "_" + fingerprint + ".json"
	return filepath.Join(dir, name), nil
}

// loadCache reads the bearer cache from disk. Returns nil (not an error) if
// the file does not exist or cannot be parsed.
func loadCache(brokerURL, fingerprint string) *bearerCache {
	path, err := cachePath(brokerURL, fingerprint)
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var bc bearerCache
	if err := json.Unmarshal(data, &bc); err != nil {
		return nil
	}
	return &bc
}

// saveCache writes the bearer cache to disk with mode 0600.
func saveCache(brokerURL, fingerprint string, bc *bearerCache) error {
	path, err := cachePath(brokerURL, fingerprint)
	if err != nil {
		return err
	}
	data, err := json.Marshal(bc)
	if err != nil {
		return fmt.Errorf("marshal cache: %w", err)
	}
	// Write atomically: write to a temp file then rename.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write cache: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename cache: %w", err)
	}
	return nil
}

// parseExpiry parses an ISO-8601 timestamp from the broker, trying RFC3339Nano
// then RFC3339 as a fallback.
func parseExpiry(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("cannot parse expiry %q as RFC3339", s)
}

// bearerCacheFromToken parses the expiry timestamps from a tokenResult and
// assembles a bearerCache. Extracted because attestFresh and renewBearer share
// identical parsing logic.
func bearerCacheFromToken(tr tokenResult) (*bearerCache, error) {
	expiresAt, err := parseExpiry(tr.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("parse expires_at: %w", err)
	}
	maxExpiresAt, err := parseExpiry(tr.MaxExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("parse max_expires_at: %w", err)
	}
	return &bearerCache{Key: tr.Key, ExpiresAt: expiresAt, MaxExpiresAt: maxExpiresAt}, nil
}
