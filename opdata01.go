package opvault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

const (
	opdataHeaderIndex         = 0
	opdataHeaderSize          = 8
	opdataPlaintextLengthSize = 8
	opdataIVSize              = 16
	opdataMACSize             = 32
	opdataMinimumLength       = opdataHeaderSize + opdataPlaintextLengthSize + opdataIVSize + 16 + opdataMACSize
)

// Encryption errors
var (
	ErrInvalidOpdata = errors.New("invalid opdata")
)

func decryptOpdata01(ciphertext, encryptionKey, macKey []byte) ([]byte, error) {
	if len(ciphertext) < opdataMinimumLength {
		return nil, ErrInvalidOpdata
	}

	// validate the mac before attempting to read any data
	data, mac := ciphertext[:len(ciphertext)-32], ciphertext[len(ciphertext)-32:]
	h := hmac.New(sha256.New, macKey)
	n, err := h.Write(data)
	if err != nil {
		return nil, err
	} else if n != len(data) {
		return nil, io.ErrShortWrite
	}

	calculatedMAC := h.Sum(nil)
	if !hmac.Equal(mac, calculatedMAC) {
		return nil, ErrInvalidOpdata
	}

	// extract/validate metadata
	if !bytes.Equal(data[:8], []byte{'o', 'p', 'd', 'a', 't', 'a', '0', '1'}) {
		return nil, ErrInvalidOpdata
	}

	var plaintextLength int64
	lengthReader := bytes.NewReader(data[8:16])
	binary.Read(lengthReader, binary.LittleEndian, &plaintextLength)

	iv, paddedData := data[16:32], data[32:]
	if len(paddedData) < int(plaintextLength) {
		return nil, ErrInvalidOpdata
	}

	// decrypt data
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(paddedData, paddedData)

	return paddedData[len(paddedData)-int(plaintextLength):], nil
}

func wipeSlice(s []byte) {
	for i := range s {
		s[i] = 0x00
	}
}
