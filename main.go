package main

import (
	"crypto/cipher"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/marko-gacesa/fenc/internal/hashgen"
	"github.com/marko-gacesa/fenc/internal/processor"
	"github.com/marko-gacesa/fenc/internal/util"
	"github.com/marko-gacesa/fenc/internal/values"

	"golang.org/x/term"
)

func main() {
	log.SetFlags(0)

	// Phase: App configuration

	config := struct {
		hashFn       string
		filesKeep    bool
		toStdout     bool
		keyUseEmpty  bool
		keyAllowWeak bool
		keyNoWarn    bool
	}{}

	flag.StringVar(&config.hashFn, "s", "sha256", "Hash function (for encryption only). Can be sha256, sha512, md5 or sha1.")
	flag.BoolVar(&config.toStdout, "o", false, "Output to stdout (for decryption only). Doesn't create output files.")
	flag.BoolVar(&config.filesKeep, "k", false, "Keep source files. Only if output is not stdout.")
	flag.BoolVar(&config.keyUseEmpty, "b", false, "Insecure. Doesn't prompt for password. Uses blank password.")
	flag.BoolVar(&config.keyAllowWeak, "u", false, "Insecure. Allow weak or empty passwords. Assumes UTF-8 encoding for keys.")
	flag.BoolVar(&config.keyNoWarn, "w", false, "Don't warn against empty key phrase.")
	flag.Parse()

	files := flag.Args()

	if len(files) == 0 {
		fmt.Println("Encrypts/decrypts files. Source files will be removed unless the -k option is used.")
		fmt.Printf("Usage: %s <options> <file_list>\n", values.AppName)
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Phase: Create hash generator

	hg, err := hashgen.FromName(config.hashFn)
	if err != nil {
		log.Fatalln(err.Error())
		return
	}

	// Phase: Prepare list of tasks

	type task struct {
		procEnc     bool
		inputFile   string
		outputFile  string
		toStdout    bool
		removeInput bool
	}

	tasks, needEncryptor, needDecryptor, err := func() (tasks []task, needEncoder, needDecoder bool, err error) {
		tasks = make([]task, 0, len(files))
		for _, file := range files {
			var t task
			t.inputFile = file

			if err = util.MustExist(t.inputFile); err != nil {
				return
			}

			if isDecoder := strings.HasSuffix(file, values.Extension); isDecoder {
				needDecoder = true
				t.procEnc = false
				t.outputFile = strings.TrimSuffix(file, values.Extension)
			} else {
				needEncoder = true
				t.procEnc = true
				t.outputFile = file + values.Extension
			}

			t.toStdout = config.toStdout && !t.procEnc       // stdout only if explicitly asked and never for encryptor output
			t.removeInput = !config.filesKeep && !t.toStdout // keeping input files only if explicitly asked and not if writing to stdout

			if !t.toStdout {
				if err = util.MustNotExist(t.outputFile); err != nil {
					return
				}
			}

			tasks = append(tasks, t)
		}

		return
	}()
	if err != nil {
		log.Fatalln(err.Error())
		return
	}

	_ = needEncryptor
	_ = needDecryptor

	// Phase: Ask for password and create cipher block

	block, err := func() (block cipher.Block, err error) {
		if config.keyUseEmpty {
			if !config.keyNoWarn && needEncryptor {
				log.Println("Warning: Using empty key phrase.")
			}

			block, err = processor.CipherBlock(nil)
			if err != nil {
				err = fmt.Errorf("failed to create empty cipher: %w", err)
				return
			}
		} else {
			log.Println("Enter encrypt key phrase: ")

			if key, errPass := term.ReadPassword(0); err != nil {
				err = fmt.Errorf("failed to read encryption key: %w", errPass)
				return
			} else {
				if len(key) == 0 && !config.keyNoWarn && needEncryptor {
					log.Println("Warning: Using empty key phrase.")
				}

				if !config.keyAllowWeak && needEncryptor {
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
						keyLen, keyHasAlpha, keyHasNum, keyHasSpec = len(key), true, true, true
					}

					if keyLen < 6 || !keyHasAlpha || !keyHasNum || !keyHasSpec {
						err = errors.New("password too weak - must be at least 6 long, must have a letter, a digit and a special character")
						return
					}
				}

				block, err = processor.CipherBlock(key)
				if err != nil {
					err = fmt.Errorf("failed to create cipher: %w", err)
					return
				}
			}
		}

		return
	}()
	if err != nil {
		log.Fatalln(err.Error())
		return
	}

	// Phase: Process each input file

	for _, t := range tasks {
		if t.procEnc {
			err = processor.EncryptFile(hg.ID, block, t.inputFile, t.outputFile)
		} else if t.toStdout {
			err = processor.DecryptToStdOut(block, t.inputFile)
		} else {
			err = processor.DecryptToFile(block, t.inputFile, t.outputFile)
		}
		if err != nil {
			if !t.toStdout {
				_ = os.Remove(t.outputFile)
			}
			break
		}

		if t.removeInput {
			err = os.Remove(t.inputFile)
			if err != nil {
				err = fmt.Errorf("failed to remove input file: %s: %w", t.inputFile, err)
				break
			}
		}
	}
	if err != nil {
		log.Fatalln(err.Error())
		return
	}
}
