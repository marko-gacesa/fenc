package processor

import (
	"bytes"
	"compress/gzip"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/marko-gacesa/cipherio"
	"github.com/marko-gacesa/fenc/internal/header"
)

var ErrorDecryptWrongKey = errors.New("decrypt failed (wrong password?)")

func Decrypt(block cipher.Block, reader io.Reader, writer io.Writer) error {
	h, err := header.Read(reader)
	if err != nil {
		return err
	}

	hasher := h.Hash()

	err = func() error {
		blockMode := cipher.NewCBCDecrypter(block, h.GetIV())
		decrypterReader := cipherio.NewBlockModeReader(blockMode, reader)

		gunzipper, err := gzip.NewReader(decrypterReader)
		if err != nil {
			return err
		}

		gunzipper.Multistream(false)

		_, err = io.Copy(io.MultiWriter(writer, hasher), gunzipper)
		if err != nil {
			return err
		}

		err = gunzipper.Close()
		if err != nil {
			return err
		}

		return err
	}()
	if err == gzip.ErrHeader || err == gzip.ErrChecksum {
		return ErrorDecryptWrongKey
	}
	if err != nil {
		return fmt.Errorf("decrypt failed: %w", err)
	}

	if !bytes.Equal(h.GetHashSum(), hasher.Sum(nil)) {
		return ErrorDecryptWrongKey
	}

	return nil
}

func DecryptToFile(block cipher.Block, inputFile, outputFile string) (err error) {
	input, err := os.Open(inputFile)
	if err != nil {
		err = fmt.Errorf("decrypt: failed to open %q: %w", inputFile, err)
		return
	}

	defer func() {
		errClose := input.Close()
		if errClose != nil && err == nil {
			err = fmt.Errorf("decrypt: failed to close %q: %w", inputFile, errClose)
		}
	}()

	output, err := os.Create(outputFile)
	if err != nil {
		err = fmt.Errorf("decrypt: failed to create %q: %w", outputFile, err)
		return
	}

	defer func() {
		errClose := output.Close()
		if errClose != nil && err == nil {
			err = fmt.Errorf("decrypt: failed to close %q: %w", outputFile, errClose)
		}
	}()

	err = Decrypt(block, input, output)

	return
}

func DecryptToStdOut(block cipher.Block, inputFile string) (err error) {
	input, err := os.Open(inputFile)
	if err != nil {
		err = fmt.Errorf("decrypt: failed to open %q: %w", inputFile, err)
		return
	}

	defer func() {
		errClose := input.Close()
		if errClose != nil && err == nil {
			err = fmt.Errorf("decrypt: failed to close %q: %w", inputFile, errClose)
		}
	}()

	err = Decrypt(block, input, os.Stdout)

	return
}
