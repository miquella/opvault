package opvault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
)

const (
	ItemCategoryLogin           ItemCategory = "001"
	ItemCategoryCreditCard      ItemCategory = "002"
	ItemCategorySecureNote      ItemCategory = "003"
	ItemCategoryIdentity        ItemCategory = "004"
	ItemCategoryPassword        ItemCategory = "005"
	ItemCategoryTombstone       ItemCategory = "099"
	ItemCategorySoftwareLicense ItemCategory = "100"
	ItemCategoryBankAccount     ItemCategory = "101"
	ItemCategoryDatabase        ItemCategory = "102"
	ItemCategoryDriverLicense   ItemCategory = "103"
	ItemCategoryOutdoorLicense  ItemCategory = "104"
	ItemCategoryMembership      ItemCategory = "105"
	ItemCategoryPassport        ItemCategory = "106"
	ItemCategoryRewards         ItemCategory = "107"
	ItemCategorySSN             ItemCategory = "108"
	ItemCategoryRouter          ItemCategory = "109"
	ItemCategoryServer          ItemCategory = "110"
	ItemCategoryEmail           ItemCategory = "111"
)

// Item errors
var (
	ErrInvalidItemKey = errors.New("invalid item key")
)

type ItemCategory string

func (ic ItemCategory) String() string {
	switch ic {
	case "001":
		return "Login"
	case "002":
		return "Credit Card"
	case "003":
		return "Secure Note"
	case "004":
		return "Identity"
	case "005":
		return "Password"
	case "099":
		return "Tombstone"
	case "100":
		return "Software License"
	case "101":
		return "Bank Account"
	case "102":
		return "Database"
	case "103":
		return "Driver License"
	case "104":
		return "Outdoor License"
	case "105":
		return "Membership"
	case "106":
		return "Passport"
	case "107":
		return "Rewards"
	case "108":
		return "SSN"
	case "109":
		return "Router"
	case "110":
		return "Server"
	case "111":
		return "Email"
	default:
		return "Unknown"
	}
}

type Item struct {
	profile *Profile

	data     map[string]interface{}
	overview map[string]interface{}
}

func (i *Item) Category() ItemCategory {
	return ItemCategory(i.getDataString("category"))
}

func (i *Item) Overview() map[string]interface{} {
	return i.overview
}

func (i *Item) Detail() (map[string]interface{}, error) {
	itemKey, itemMAC, err := i.itemKeys()
	if err != nil {
		return nil, err
	}

	detailData, err := decryptOpdata01(i.getDataBytes("d"), itemKey, itemMAC)
	if err != nil {
		return nil, err
	}

	detail := make(map[string]interface{})
	err = json.Unmarshal(detailData, &detail)
	if err != nil {
		return nil, err
	}

	return detail, nil
}

func (i *Item) itemKeys() ([]byte, []byte, error) {
	k := i.getDataBytes("k")
	if len(k) == 0 {
		return nil, nil, ErrInvalidItemKey
	}

	// get master keys
	masterKey, masterMAC, err := i.profile.masterKeys()
	if err != nil {
		return nil, nil, err
	}

	// validate item keys
	data, mac := k[:len(k)-32], k[len(k)-32:]
	h := hmac.New(sha256.New, masterMAC)
	n, err := h.Write(data)
	if err != nil {
		return nil, nil, err
	} else if n != len(data) {
		return nil, nil, io.ErrShortWrite
	}

	calculatedMAC := h.Sum(nil)
	if !hmac.Equal(mac, calculatedMAC) {
		return nil, nil, ErrInvalidItemKey
	}

	// decrypt item keys
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, nil, err
	}

	cbc := cipher.NewCBCDecrypter(block, data[:16])
	keys := make([]byte, len(data)-16)
	copy(keys, data[16:])
	cbc.CryptBlocks(keys, keys)

	return keys[len(keys)-64 : len(keys)-32], keys[len(keys)-32:], nil
}

func (i *Item) getDataString(key string) string {
	str, _ := i.data[key].(string)
	return str
}

func (i *Item) getDataBytes(key string) []byte {
	str, _ := i.data[key].(string)
	if str == "" {
		return nil
	}

	data, _ := base64.StdEncoding.DecodeString(str)
	return data
}

func readItem(profile *Profile, data map[string]interface{}) (*Item, error) {
	item := &Item{
		profile: profile,
		data:    data,
	}

	overviewData := item.getDataBytes("o")
	if len(overviewData) == 0 {
		return item, nil
	}

	// decrypt overview data
	overviewKey, overviewMAC, err := item.profile.overviewKeys()
	if err != nil {
		return nil, err
	}

	decryptedOverviewData, err := decryptOpdata01(overviewData, overviewKey, overviewMAC)
	if err != nil {
		return nil, err
	}

	// decode overview data
	item.overview = make(map[string]interface{})
	err = json.Unmarshal(decryptedOverviewData, &item.overview)
	if err != nil {
		return nil, err
	}

	return item, nil
}
