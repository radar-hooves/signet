// bearer.go: the one path every subcommand takes to hold a bearer — disk cache
// first, renew near expiry, fresh attestation last, single-flighted across
// processes.
//
// Every subcommand needs the same thing (a live bearer) but only `auth` used to
// consult the cache; `headers`, `exec`, `vend-to-file` and `verify` each called
// attestFresh directly. That is three broker round-trips and a hardware
// signature per invocation, and the invocations are not spread out: a Claude
// Code session with N gate-served MCP servers runs N headersHelper processes at
// once. Measured 2026-08-14 on a 26-server project — 26 concurrent
// attestations, a median 12s and worst-case 29s to return a header, and the
// broker (correctly) shedding load with 429s and 401s. Claude Code read the
// failures as an auth-discovery problem and reported "Incompatible auth server:
// does not support dynamic client registration" against every one of them.
package attest

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/radar-hooves/signet/internal/signer"
)

// renewWindow is how close to expiry a cached bearer is renewed rather than
// reused. Shared by the cache read below and documented in docs/usage.md.
const renewWindow = 30 * time.Minute

// bearer returns a live bearer for this broker: the cached one while it is
// healthy, a renewed one near expiry, a freshly attested one otherwise.
//
// Concurrent callers single-flight through a lock on the cache file, so a cold
// or expired cache costs ONE attestation however many processes want it — the
// stampede is the failure mode this exists to prevent, and it is exactly what a
// session start produces. A caller that cannot take the lock still proceeds
// (locking is an optimisation, never a correctness gate), so a platform without
// it, or a stale lock, degrades to the old behaviour rather than blocking.
func bearer(s signer.Signer, brokerURL string) (*bearerCache, error) {
	spkiB64, err := s.PublicKeyDER()
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}
	fingerprint, err := publicKeyFingerprint(spkiB64)
	if err != nil {
		return nil, fmt.Errorf("compute key fingerprint: %w", err)
	}

	if bc := usableCache(brokerURL, fingerprint); bc != nil {
		return bc, nil
	}

	// Cache missing, expired, or inside the renew window. Serialise here: the
	// holder does the work, the waiters re-read what it wrote. A timeout means
	// the lock is genuinely still held past one mint's worth of time — report
	// it, then proceed unlocked rather than block forever or fail this caller.
	unlock, lockErr := lockCache(brokerURL, fingerprint)
	if lockErr != nil {
		fmt.Fprintf(os.Stderr, "signet: %v; minting our own\n", lockErr)
	}
	defer unlock()

	// Re-check under the lock — a waiter released here almost always finds the
	// bearer the holder just minted, which is the whole point.
	if bc := usableCache(brokerURL, fingerprint); bc != nil {
		return bc, nil
	}

	if cached := loadCache(brokerURL, fingerprint); cached != nil {
		if time.Until(cached.ExpiresAt) > 0 && time.Until(cached.MaxExpiresAt) > 0 {
			// Inside the renew window: leg 3 is one round-trip against three.
			renewed, renewErr := renewBearer(brokerURL, cached.Key)
			if renewErr != nil {
				fmt.Fprintf(os.Stderr, "signet: renew failed, re-attesting: %v\n", renewErr)
			} else if renewed != nil {
				_ = saveCache(brokerURL, fingerprint, renewed)
				return renewed, nil
			}
			// renewed == nil means the broker returned 401 (past max lifetime);
			// fall through to a fresh attestation.
		}
	}

	bc, err := attestFresh(s, brokerURL)
	if err != nil {
		return nil, err
	}
	// Best-effort: an uncacheable bearer is still a usable one.
	_ = saveCache(brokerURL, fingerprint, bc)
	return bc, nil
}

// usableCache returns the cached bearer when it is live and comfortably clear
// of expiry, else nil. "Comfortably" is renewWindow: a bearer inside it is
// renewed rather than handed out, so a long-running consumer never receives one
// about to expire mid-use.
func usableCache(brokerURL, fingerprint string) *bearerCache {
	cached := loadCache(brokerURL, fingerprint)
	if cached == nil {
		return nil
	}
	if time.Until(cached.MaxExpiresAt) <= 0 {
		return nil
	}
	if time.Until(cached.ExpiresAt) <= renewWindow {
		return nil
	}
	return cached
}

// refreshBearer discards a bearer the broker has refused and mints a
// replacement, single-flighted like bearer() so a session's worth of processes
// recovering from the same rotation costs one attestation between them.
//
// refusedKey is the bearer just refused. A caller that waited for the lock will
// usually find another process has already replaced it; taking that one rather
// than minting a second is what stops the recovery becoming its own stampede.
func refreshBearer(s signer.Signer, brokerURL, refusedKey string) (*bearerCache, error) {
	spkiB64, err := s.PublicKeyDER()
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}
	fingerprint, err := publicKeyFingerprint(spkiB64)
	if err != nil {
		return nil, fmt.Errorf("compute key fingerprint: %w", err)
	}

	unlock, lockErr := lockCache(brokerURL, fingerprint)
	if lockErr != nil {
		fmt.Fprintf(os.Stderr, "signet: %v; minting our own\n", lockErr)
	}
	defer unlock()

	if cached := loadCache(brokerURL, fingerprint); cached != nil && cached.Key != refusedKey {
		return cached, nil
	}

	bc, err := attestFresh(s, brokerURL)
	if err != nil {
		return nil, err
	}
	// Overwriting the cache IS the invalidation: saveCache replaces by rename,
	// so no window exists in which the refused bearer is still the cached one.
	_ = saveCache(brokerURL, fingerprint, bc)
	return bc, nil
}

// vendCredential performs the credential vend, re-attesting once if the broker
// refuses the bearer.
//
// A cached bearer can be dead well before its local expiry. The broker deletes
// the old key when a renew rotates it (rotate_key inserts the new and deletes
// the old in one transaction), so a process that read the cache moments before
// another renewed it holds a key the broker no longer knows. Nothing local says
// so — the cached copy still looks fresh, so it is handed out until it enters
// the renew window, and the SAME dead key is presented on every invocation for
// up to renewWindow. Five refusals inside fifteen minutes trip the broker's
// per-key auth-failure lock, and then EVERY credential that identity vends
// answers 429 until the window rolls: one stale bearer takes out the whole
// identity. Measured 2026-08-27 on a live fleet — two unrelated credentials
// locked out together, neither of them the one whose renew rotated the key.
//
// The broker's own lock is written against a consumer that "occasionally
// presents an old key before rotating", which is exactly what signet was not
// doing. This makes that assumption true.
//
// 15-attest-boundary.md §3: a 401 is the broker exercising its authority and the
// only response is to re-attest. That already held on the renew leg
// (renewBearer) and in auth; the vend door — §1's one bounded exception — never
// got it. 429 is deliberately NOT retried: that is the broker shedding load or
// the lock already tripped, and a retry there compounds both.
func vendCredential(s signer.Signer, brokerURL, endpoint string, bc *bearerCache) (int, []byte, error) {
	status, body, err := brokerGet(endpoint, bc.Key)
	if err != nil || status != http.StatusUnauthorized {
		return status, body, err
	}

	// Exactly one retry: a genuinely unauthorised caller still fails fast, and a
	// broker refusing every bearer never sees a loop.
	fresh, refreshErr := refreshBearer(s, brokerURL, bc.Key)
	if refreshErr != nil {
		// Report the broker's original refusal, not the retry's failure: the 401
		// is what the caller must act on, and its exit code is already mapped.
		return status, body, nil
	}
	return brokerGet(endpoint, fresh.Key)
}
