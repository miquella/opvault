package opvault

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"
)

type Profile struct {
	vault   *Vault
	profile string

	data map[string]interface{}
}

func (p *Profile) Profile() string {
	return p.profile
}

func (p *Profile) ProfileName() string {
	return p.getDataString("profileName")
}

func (p *Profile) Uuid() string {
	return p.getDataString("uuid")
}

func (p *Profile) PasswordHint() string {
	return p.getDataString("passwordHint")
}

func (p *Profile) Salt() []byte {
	return p.getDataBytes("salt")
}

func (p *Profile) Iterations() int {
	return p.getDataInt("iterations")
}

func (p *Profile) CreatedAt() time.Time {
	return time.Unix(p.getDataInt64("createdAt"), 0)
}

func (p *Profile) UpdatedAt() time.Time {
	return time.Unix(p.getDataInt64("updatedAt"), 0)
}

func (p *Profile) getDataInt(key string) int {
	val, _ := p.data[key].(float64)
	return int(val)
}

func (p *Profile) getDataInt64(key string) int64 {
	val, _ := p.data[key].(float64)
	return int64(val)
}

func (p *Profile) getDataString(key string) string {
	str, _ := p.data[key].(string)
	return str
}

func (p *Profile) getDataBytes(key string) []byte {
	str, _ := p.data[key].(string)
	if str == "" {
		return nil
	}

	data, _ := base64.StdEncoding.DecodeString(str)
	return data
}

func (p *Profile) readData() error {
	f, err := os.Open(filepath.Join(p.vault.dir, p.profile, "profile.js"))
	if err != nil {
		return err
	}
	defer f.Close()

	preamble := make([]byte, 12)
	_, err = io.ReadAtLeast(f, preamble, 12)
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			return ErrInvalidProfile
		} else {
			return err
		}
	}
	if string(preamble) != "var profile=" {
		return ErrInvalidProfile
	}

	d := json.NewDecoder(f)
	err = d.Decode(&p.data)
	if err != nil {
		return ErrInvalidProfile
	}

	return nil
}
