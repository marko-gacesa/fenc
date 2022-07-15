package processor

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/marko-gacesa/cipherio"
)

func CipherBlock(keyPhrase []byte) (block cipher.Block, err error) {
	var key []byte

	const (
		aes256 = aes.BlockSize * 2
		aes192 = aes.BlockSize * 1.5
		aes128 = aes.BlockSize
	)

	if l := len(keyPhrase); l == 0 {
		key = make([]byte, aes.BlockSize)
	} else if l == aes256 || l == aes192 || l == aes128 {
		key = keyPhrase
	} else if l > aes256 {
		key = keyPhrase[:aes256]
	} else if l > aes192 { // l is 25..31
		key = cipherio.FitToBlock(keyPhrase, aes256)
	} else if l > aes128 { // l is 17..23
		key = cipherio.FitToBlock(keyPhrase, aes192)
	} else { // l is 1..15
		key = cipherio.FitToBlock(keyPhrase, aes128)
	}

	block, err = aes.NewCipher(key)
	if err != nil {
		return
	}

	return
}
