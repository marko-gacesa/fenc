package processor

import (
	"compress/gzip"
	"crypto/cipher"
	"fmt"
	"io"
	"os"

	"github.com/marko-gacesa/cipherio"
	"github.com/marko-gacesa/fenc/internal/header"
)

func Encrypt(hashID uint, block cipher.Block, iv []byte, reader io.Reader, writer io.WriteSeeker) (*header.Header, error) {
	h := header.New(hashID, iv)

	hasher := h.Hash()

	if err := h.Write(writer); err != nil {
		return nil, err
	}

	copyData := func() error {
		blockMode := cipher.NewCBCEncrypter(block, h.GetIV())
		encrypterWriter := cipherio.NewBlockModeWriter(blockMode, writer)
		gzipper := gzip.NewWriter(encrypterWriter)

		_, err := io.Copy(io.MultiWriter(gzipper, hasher), reader)
		if err != nil {
			return err
		}

		err = gzipper.Close()
		if err != nil {
			return err
		}

		err = encrypterWriter.Close()
		if err != nil {
			return err
		}

		return nil
	}
	if err := copyData(); err != nil {
		return nil, fmt.Errorf("encrypt failed: %w", err)
	}

	h.SetHashSum(hasher.Sum(nil))

	if err := h.Update(writer); err != nil {
		return nil, err
	}

	return h, nil
}

func EncryptFile(hashID uint, block cipher.Block, inputFile, outputFile string) (err error) {
	input, err := os.Open(inputFile)
	if err != nil {
		err = fmt.Errorf("encrypt: failed to open %q: %w", inputFile, err)
		return
	}

	defer func() {
		errClose := input.Close()
		if errClose != nil && err == nil {
			err = fmt.Errorf("encrypt: failed to close %q: %w", inputFile, errClose)
		}
	}()

	output, err := os.Create(outputFile)
	if err != nil {
		err = fmt.Errorf("encrypt: failed to create %q: %w", outputFile, err)
		return
	}

	defer func() {
		errClose := output.Close()
		if errClose != nil && err == nil {
			err = fmt.Errorf("encrypt: failed to close %q: %w", outputFile, errClose)
		}
	}()

	_, err = Encrypt(hashID, block, cipherio.RandIV(block), input, output)

	return
}
