package opvault

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
)

// Vault Errors
var (
	ErrVaultMustBeDir = errors.New("vault must be a directory")
)

type Vault struct {
	dir string
}

func Open(dir string) (*Vault, error) {
	dirStat, err := os.Stat(dir)
	if err != nil {
		return nil, err.(*os.PathError).Err
	}

	if !dirStat.IsDir() {
		return nil, ErrVaultMustBeDir
	}

	return &Vault{dir}, nil
}

func (v *Vault) ProfileNames() ([]string, error) {
	entries, err := ioutil.ReadDir(v.dir)
	if err != nil {
		return nil, err
	}

	profiles := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			profileStat, err := os.Stat(filepath.Join(v.dir, entry.Name(), "profile.js"))
			if err == nil && profileStat.Mode().IsRegular() {
				profiles = append(profiles, entry.Name())
			}
		}
	}

	return profiles, nil
}
