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
	ErrInvalidProfile = errors.New("invalid profile")
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

func (v *Vault) Profile(profile string) (*Profile, error) {
	profileStat, err := os.Stat(filepath.Join(v.dir, profile, "profile.js"))
	if err != nil {
		if err.(*os.PathError).Err == os.ErrNotExist {
			return nil, ErrInvalidProfile
		}
		return nil, err.(*os.PathError).Err
	}

	if !profileStat.Mode().IsRegular() {
		return nil, ErrInvalidProfile
	}

	p := &Profile{
		vault:   v,
		profile: profile,
		data:    make(map[string]interface{}),
	}
	err = p.readData()
	if err != nil {
		return nil, err
	}

	return p, nil
}
