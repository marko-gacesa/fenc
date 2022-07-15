package processor

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"strings"
	"testing"
)

func TestDecrypt(t *testing.T) {
	tests := []struct {
		name       string
		data       string
		encryptKey string
		decryptKey string
		expErr     error
	}{
		{
			name:       "empty",
			data:       "",
			encryptKey: testKey,
			decryptKey: testKey,
		},
		{
			name:       "lorem_ipsum",
			data:       loremIpsum,
			encryptKey: testKey,
			decryptKey: testKey,
		},
		{
			name:       "wrong_pass",
			data:       loremIpsum,
			encryptKey: testKey,
			decryptKey: "a-wrong-password",
			expErr:     ErrorDecryptWrongKey,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encryptBlock, _ := aes.NewCipher([]byte(test.encryptKey))
			data := test.data

			buf := &seekBuffer{}
			_, err := Encrypt(uint(crypto.MD5), encryptBlock, []byte(testIV), strings.NewReader(data), buf)
			if err != nil {
				t.Errorf("failed to prepare encrypted data: %v", err)
				return
			}

			decryptBlock, _ := aes.NewCipher([]byte(test.decryptKey))

			outputBuffer := bytes.NewBuffer(nil)
			err = Decrypt(decryptBlock, bytes.NewReader(buf.data), outputBuffer)
			if got, want := err, test.expErr; got != want {
				t.Errorf("error mismatch: got=%v want=%v", got, want)
				return
			}

			if err != nil {
				return
			}

			if got, want := outputBuffer.String(), data; got != want {
				t.Errorf("data mismatch: got=%s want=%s", got, want)
				return
			}
		})
	}
}
