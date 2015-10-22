package opvault

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// Profile errors
var (
	ErrInvalidPassword = errors.New("invalid password")
	ErrInvalidBand     = errors.New("invalid band")
	ErrProfileLocked   = errors.New("profile locked")
)

type Profile struct {
	vault   *Vault
	profile string

	derivedKey []byte
	derivedMAC []byte

	data map[string]interface{}
}

func (p *Profile) Unlock(password string) error {
	key := pbkdf2.Key([]byte(password), p.Salt(), p.Iterations(), 64, sha512.New)
	p.derivedKey, p.derivedMAC = key[:32], key[32:]

	masterKey, err := decryptOpdata01(p.getDataBytes("masterKey"), p.derivedKey, p.derivedMAC)
	if err != nil {
		if err == ErrInvalidOpdata {
			return ErrInvalidPassword
		}
		return err
	}

	wipeSlice(masterKey)
	return nil
}

func (p *Profile) Lock() {
	wipeSlice(p.derivedKey)
	p.derivedKey = nil

	wipeSlice(p.derivedMAC)
	p.derivedMAC = nil
}

func (p *Profile) Profile() string {
	return p.profile
}

func (p *Profile) ProfileName() string {
	return p.getDataString("profileName")
}

func (p *Profile) UUID() string {
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

func (p *Profile) Items() ([]*Item, error) {
	items, err := p.readBands()
	if err != nil {
		return nil, err
	}

	return items, nil
}

func (p *Profile) overviewKeys() ([]byte, []byte, error) {
	if p.derivedKey == nil || p.derivedMAC == nil {
		return nil, nil, ErrProfileLocked
	}

	decryptedOverviewKey, err := decryptOpdata01(p.getDataBytes("overviewKey"), p.derivedKey, p.derivedMAC)
	if err != nil {
		return nil, nil, err
	}

	d := sha512.New()
	d.Write(decryptedOverviewKey)
	keys := d.Sum(nil)

	return keys[:32], keys[32:], nil
}

func (p *Profile) masterKeys() ([]byte, []byte, error) {
	if p.derivedKey == nil || p.derivedMAC == nil {
		return nil, nil, ErrProfileLocked
	}

	decryptedMasterKey, err := decryptOpdata01(p.getDataBytes("masterKey"), p.derivedKey, p.derivedMAC)
	if err != nil {
		return nil, nil, err
	}

	d := sha512.New()
	d.Write(decryptedMasterKey)
	keys := d.Sum(nil)

	return keys[:32], keys[32:], nil
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
		}
		return err
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

func (p *Profile) readBands() ([]*Item, error) {
	bands, err := filepath.Glob(filepath.Join(p.vault.dir, p.profile, "band_[0123456789ABCDEF].js"))
	if err != nil {
		return nil, err
	}

	items := []*Item{}
	for _, band := range bands {
		bandItems, err := p.readBand(band)
		if err != nil {
			return nil, err
		}

		items = append(items, bandItems...)
	}

	return items, nil
}

func (p *Profile) readBand(bandPath string) ([]*Item, error) {
	f, err := os.Open(bandPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	preamble := make([]byte, 3)
	_, err = io.ReadAtLeast(f, preamble, 3)
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, ErrInvalidBand
		}
		return nil, err
	}
	if string(preamble) != "ld(" {
		return nil, ErrInvalidBand
	}

	bandData := make(map[string]map[string]interface{})
	d := json.NewDecoder(f)
	err = d.Decode(&bandData)
	if err != nil {
		return nil, ErrInvalidBand
	}

	items := []*Item{}
	for _, data := range bandData {
		item, err := readItem(p, data)
		if err != nil {
			log.Printf("WARNING: cannot read item")
			continue
		}

		items = append(items, item)
	}

	return items, nil
}
