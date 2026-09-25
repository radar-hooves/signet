// Package datadir locates signet's single data directory (~/.signet).
//
// The bearer cache lives under this one dotfolder (the household ~/.tool
// convention, not an XDG split across ~/.local/share and ~/.cache). The
// signing key itself lives elsewhere, at $XDG_CONFIG_HOME/portcullis
// (internal/signer.DefaultKeyPath), the path the household's vend-token.py
// also uses.
package datadir

import (
	"fmt"
	"os"
	"path/filepath"
)

// Path returns signet's data directory (~/.signet). The directory is not
// created here; each owner creates the subtree it needs with the modes it
// needs (0700 directories, 0600 files).
func Path() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(home, ".signet"), nil
}
