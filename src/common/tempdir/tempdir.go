// Package tempdir creates project-scoped temporary directories under the OS temp root.
package tempdir

import (
	"os"
	"path/filepath"

	"github.com/apimgr/whois/src/common/constants"
)

// Create makes an owner-only directory named for this project's stable identity.
func Create() (string, error) {
	base := filepath.Join(os.TempDir(), constants.InternalOrg)
	if err := os.MkdirAll(base, 0700); err != nil {
		return "", err
	}
	if err := os.Chmod(base, 0700); err != nil {
		return "", err
	}
	return os.MkdirTemp(base, constants.InternalName+"-")
}
