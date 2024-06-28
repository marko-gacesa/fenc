package password

import (
	"bytes"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"
)

func Input(strength, retype bool) ([]byte, error) {
	key, err := input("Enter key phrase: ")
	if err != nil {
		return nil, err
	}

	if strength && len(key) == 0 {
		return nil, errors.New("empty key phrase not allowed")
	}

	if strength && !verifyStrength(key) {
		return nil, errors.New("too weak - must be at least 6 long, must have a letter, a digit and a special character")
	}

	if !retype {
		return key, nil
	}

	key2, err := input("Enter key phrase again: ")
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(key, key2) {
		return nil, errors.New("key phrases do not match")
	}

	return key, nil
}

func input(query string) ([]byte, error) {
	fmt.Print(query)
	defer fmt.Println()

	key, err := term.ReadPassword(0)
	if err != nil {
		return nil, fmt.Errorf("failed to read encryption key: %w", err)
	}

	return key, nil
}

func verifyStrength(key []byte) bool {
	var (
		keyLen      int
		keyHasAlpha bool
		keyHasNum   bool
		keyHasSpec  bool
	)

	if utf8.Valid(key) {
		for i := 0; i < len(key); {
			r, size := utf8.DecodeRune(key[i:])
			i += size

			keyLen++
			keyHasAlpha = keyHasAlpha || unicode.IsLetter(r)
			keyHasNum = keyHasNum || unicode.IsNumber(r)
			keyHasSpec = keyHasSpec || (!unicode.IsLetter(r) && !unicode.IsNumber(r))
		}
	} else {
		return true
	}

	return keyLen >= 6 && keyHasAlpha && keyHasNum && keyHasSpec
}
