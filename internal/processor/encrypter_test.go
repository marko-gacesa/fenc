package processor

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/marko-gacesa/cipherio"
	"github.com/marko-gacesa/fenc/internal/hashgen"
	"github.com/marko-gacesa/fenc/internal/header"
)

const (
	testKey    = "16-byte-long-key"
	testIV     = "not_so_random_iv"
	loremIpsum = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum"
)

func TestEncrypt(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
		data string
		iv   []byte
	}{
		{
			name: "empty",
			key:  []byte(testKey),
			data: "",
			iv:   []byte(testIV),
		},
		{
			name: "lorem_ipsum",
			key:  []byte(testKey),
			data: loremIpsum,
			iv:   []byte(testIV),
		},
		{
			name: "long_producing_small_output",
			key:  []byte(testKey),
			data: strings.Repeat("1234", 873) + strings.Repeat("ABC", 423) + strings.Repeat("qwerty", 653),
			iv:   []byte(testIV),
		},
	}

	hg, _ := hashgen.FromName("md5")

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			block, _ := aes.NewCipher(test.key)

			wantBytes, err := _produceControlledEncryptedData(block, test.iv, []byte(test.data))
			if err != nil {
				t.Errorf("failed to prepare encrypted data: %v", err)
				return
			}

			gotBuffer := &seekBuffer{}
			h, err := Encrypt(hg.ID, block, test.iv, strings.NewReader(test.data), gotBuffer)
			if err != nil {
				t.Errorf("failed to encrypt data: %v", err)
				return
			}
			gotBytes := gotBuffer.data

			fmt.Printf("%+v\n", h)

			if got, want := len(gotBytes)-header.Size, len(wantBytes); got != want {
				t.Errorf("final size mismatch: got=%d want=%d", got, want)
			}

			if got, want := wantBytes, gotBytes[header.Size:]; !bytes.Equal(got, want) {
				t.Error("data mismatch")
			}
		})
	}
}

func _produceControlledEncryptedData(block cipher.Block, iv, data []byte) (output []byte, err error) {
	gzipperBuffer := bytes.NewBuffer(nil)
	gzipper := gzip.NewWriter(gzipperBuffer)
	_, err = gzipper.Write(data)
	if err != nil {
		return
	}
	err = gzipper.Close()
	if err != nil {
		return
	}

	blockMode := cipher.NewCBCEncrypter(block, iv)
	encryptBuffer := bytes.NewBuffer(nil)
	encryptWriter := cipherio.NewBlockModeWriter(blockMode, encryptBuffer)
	_, err = encryptWriter.Write(gzipperBuffer.Bytes())
	if err != nil {
		return
	}
	err = encryptWriter.Close()
	if err != nil {
		return
	}

	output = encryptBuffer.Bytes()

	return
}

type seekBuffer struct {
	cur  int
	size int
	data []byte
}

func (b *seekBuffer) Write(chunk []byte) (n int, err error) {
	available := b.size - b.cur
	if available >= len(chunk) {
		copy(b.data[b.cur:b.cur+len(chunk)], chunk)
	} else {
		copy(b.data[b.cur:b.cur+available], chunk[:available])
		b.data = append(b.data, chunk[available:]...)
		b.size += len(chunk[available:])
	}
	b.cur += len(chunk)

	return len(chunk), nil
}

func (b *seekBuffer) Seek(offset int64, whence int) (int64, error) {
	if offset > int64(b.size) {
		return 0, io.ErrUnexpectedEOF
	}
	b.cur = int(offset)
	return offset, nil
}
