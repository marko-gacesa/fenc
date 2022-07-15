package util

import (
	"fmt"
	"os"
)

func MustExist(fileName string) error {
	fileInfo, err := os.Stat(fileName)
	if err != nil && os.IsNotExist(err) {
		return fmt.Errorf("file not exists: %q", fileName)
	} else if err != nil {
		return fmt.Errorf("failed to access file %q: %w", fileName, err)
	}

	if fileInfo.IsDir() {
		return fmt.Errorf("file is a directory: %q", fileName)
	}

	return nil
}

func MustNotExist(fileName string) error {
	fileInfo, err := os.Stat(fileName)
	if err != nil && os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to access file %q: %w", fileName, err)
	}

	if fileInfo.IsDir() {
		return fmt.Errorf("file is a directory: %q", fileName)
	}

	return fmt.Errorf("file already exist: %q", fileName)
}
