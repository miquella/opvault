package opvault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
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

	data     dataMap
	overview dataMap
}

func (i *Item) Category() ItemCategory {
	return ItemCategory(i.data.getString("category"))
}

func (i *Item) Title() string {
	return i.overview.getString("title")
}

func (i *Item) Url() string {
	return i.overview.getString("url")
}

func (i *Item) Trashed() bool {
	return i.overview.getBool("trashed")
}

func (i *Item) Tags() []string {
	return i.overview.getStringSlice("tags")
}

func (i *Item) Detail() (*ItemDetail, error) {
	itemKey, itemMAC, err := i.itemKeys()
	if err != nil {
		return nil, err
	}

	detailData, err := decryptOpdata01(i.data.getBytes("d"), itemKey, itemMAC)
	if err != nil {
		return nil, err
	}

	detail := &ItemDetail{make(dataMap)}
	err = json.Unmarshal(detailData, &detail.data)
	if err != nil {
		return nil, err
	}

	return detail, nil
}

func (i *Item) itemKeys() ([]byte, []byte, error) {
	k := i.data.getBytes("k")
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

func readItem(profile *Profile, data map[string]interface{}) (*Item, error) {
	item := &Item{
		profile: profile,
		data:    data,
	}

	// TODO: validate hmac

	overviewData := item.data.getBytes("o")
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

type ItemDetail struct {
	data dataMap
}

func (id *ItemDetail) Fields() []*Field {
	fieldMaps := id.data.getMapSlice("fields")

	fields := []*Field{}
	for _, fieldMap := range fieldMaps {
		fields = append(fields, &Field{fieldMap})
	}

	return fields
}

func (id *ItemDetail) Notes() string {
	return id.data.getString("notesPlain")
}

func (id *ItemDetail) Sections() []*Section {
	sectionMaps := id.data.getMapSlice("sections")

	sections := []*Section{}
	for _, sectionMap := range sectionMaps {
		sections = append(sections, &Section{sectionMap})
	}

	return sections
}

type Field struct {
	data dataMap
}

type FieldType string

const (
	PasswordFieldType  FieldType = "P"
	TextFieldType      FieldType = "T"
	EmailFieldType     FieldType = "E"
	NumberFieldType    FieldType = "N"
	RadioFieldType     FieldType = "R"
	TelephoneFieldType FieldType = "TEL"
	CheckboxFieldType  FieldType = "C"
	URLFieldType       FieldType = "U"
)

type FieldDesignation string

const (
	NoDesignation       FieldDesignation = ""
	UsernameDesignation FieldDesignation = "username"
	PasswordDesignation FieldDesignation = "password"
)

func (f *Field) Type() FieldType {
	return FieldType(f.data.getString("type"))
}

func (f *Field) Name() string {
	return f.data.getString("name")
}

func (f *Field) Value() string {
	return f.data.getString("value")
}

func (f *Field) Designation() FieldDesignation {
	return FieldDesignation(f.data.getString("designation"))
}

type Section struct {
	data dataMap
}

func (s *Section) Name() string {
	return s.data.getString("name")
}

func (s *Section) Title() string {
	return s.data.getString("title")
}

func (s *Section) Fields() []*SectionField {
	fieldMaps := s.data.getMapSlice("fields")

	fields := []*SectionField{}
	for _, fieldMap := range fieldMaps {
		fields = append(fields, &SectionField{fieldMap})
	}

	return fields
}

type SectionField struct {
	data dataMap
}

type FieldKind string

const (
	ConcealedFieldKind FieldKind = "concealed"
	AddressFieldKind   FieldKind = "address"
	DateFieldKind      FieldKind = "date"
	MonthYearFieldKind FieldKind = "monthYear"
	StringFieldKind    FieldKind = "string"
	URLFieldKind       FieldKind = "URL"
	CCTypeFieldKind    FieldKind = "cctype"
	PhoneFieldKind     FieldKind = "phone"
	GenderFieldKind    FieldKind = "gender"
	EmailFieldKind     FieldKind = "email"
	MenuFieldKind      FieldKind = "menu"
)

func (f *SectionField) Kind() FieldKind {
	return FieldKind(f.data.getString("k"))
}

func (f *SectionField) Name() string {
	return f.data.getString("n")
}

func (f *SectionField) Title() string {
	return f.data.getString("t")
}

func (f *SectionField) Value() string {
	return f.data.getString("v")
}
