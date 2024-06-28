package main

import (
	"crypto/cipher"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/marko-gacesa/fenc/internal/file"
	"github.com/marko-gacesa/fenc/internal/hashgen"
	"github.com/marko-gacesa/fenc/internal/password"
	"github.com/marko-gacesa/fenc/internal/printer"
	"github.com/marko-gacesa/fenc/internal/processor"
	"github.com/marko-gacesa/fenc/internal/task"
	"github.com/marko-gacesa/fenc/internal/values"
)

const version = "1.0.0"

const defaultKeyPhraseEnv = "FENC_KEY_PHRASE"

func main() {
	log.SetFlags(0)

	// Phase: App configuration

	options := struct {
		hashFn       string
		outStd       bool
		outNoColor   bool
		outQuiet     bool
		filesKeep    bool
		keyUseEmpty  bool
		keyRaw       string
		keyEnv       string
		keyAllowWeak bool
		keyNoWarn    bool
		showVersion  bool
		showHelp     bool
	}{}

	flag.StringVar(&options.hashFn, "s", "sha256", "Hash function (for encryption only). Can be sha256, sha512, md5 or sha1.")
	flag.BoolVar(&options.outStd, "o", false, "Output to stdout (for decryption only). Don't create output files.")
	flag.BoolVar(&options.outNoColor, "c", false, "Disable color output.")
	flag.BoolVar(&options.outQuiet, "q", false, "Suppress progress output. It's always suppressed if output is stdout.")
	flag.BoolVar(&options.filesKeep, "k", false, "Keep source files. Only if output is not stdout.")
	flag.BoolVar(&options.keyUseEmpty, "b", false, "Insecure. Don't prompt for the key phrase. Use blank key phrase.")
	flag.StringVar(&options.keyRaw, "p", "", "Use the provided value as the key phrase.")
	flag.StringVar(&options.keyEnv, "P", "", "Use key phrase from the provided environment variable.")
	flag.BoolVar(&options.keyAllowWeak, "u", false, "Insecure. Allow weak or empty passwords. Assume UTF-8 encoding for keys.")
	flag.BoolVar(&options.keyNoWarn, "w", false, "Don't warn against empty key phrase.")
	flag.BoolVar(&options.showVersion, "v", false, "Display version and exit.")
	flag.BoolVar(&options.showHelp, "h", false, "Display usage information and exit.")
	flag.Parse()

	fileNameList := flag.Args()

	if options.showVersion {
		fmt.Println(version)
		return
	}

	if len(fileNameList) == 0 || options.showHelp {
		fmt.Println("Encrypts/decrypts files. Source files will be removed unless the -k option is used.")
		fmt.Println("Newly encrypted files get the '.fenc' extension. Decrypted files lose the '.fenc' extension.")
		fmt.Println()
		fmt.Printf("Usage: %s <options> <file_list>\n", values.AppName)
		fmt.Println()
		fmt.Println("Options:")
		flag.PrintDefaults()
		return
	}

	// Phase: Validate and sanitize options

	err := func() error {
		if options.outStd {
			options.outQuiet = true
		}

		if options.keyEnv != "" {
			if options.keyRaw != "" {
				return errors.New("can't use both, the key phrase environment variable and the raw key phrase")
			}

			if options.keyUseEmpty {
				return errors.New("can't use both, the key phrase environment variable and request empty key phrase")
			}

			if keyRaw, ok := os.LookupEnv(options.keyEnv); !ok || keyRaw == "" {
				return errors.New("environment variable for key phrase is not defined or has no value")
			} else {
				options.keyRaw = keyRaw
			}
		} else if options.keyRaw != "" {
			if options.keyUseEmpty {
				return errors.New("can't use both, the raw key phrase and request empty key phrase")
			}
		} else if !options.keyUseEmpty {
			if keyRaw, ok := os.LookupEnv(defaultKeyPhraseEnv); ok {
				options.keyRaw = keyRaw
			}
		}

		return nil
	}()
	if err != nil {
		log.Fatalf("Options error: %s", err.Error())
		return
	}

	// Phase: Create hash generator

	hg, err := hashgen.FromName(options.hashFn)
	if err != nil {
		log.Fatalf("Hash function error: %s", err.Error())
		return
	}

	// Phase: Prepare list of tasks

	tasks, needEncryptor, needDecryptor, err := func() (tasks []task.Task, needEncryptor, needDecryptor bool, err error) {
		tasks = make([]task.Task, len(fileNameList))
		for i, fileName := range fileNameList {
			var t task.Task
			t.InputFile = fileName

			if err = file.MustBeReadable(t.InputFile); err != nil {
				return
			}

			if isEncrypted := strings.HasSuffix(fileName, values.Extension); isEncrypted {
				needDecryptor = true
				t.ProcEnc = false
				t.OutputFile = strings.TrimSuffix(fileName, values.Extension)
			} else {
				needEncryptor = true
				t.ProcEnc = true
				t.OutputFile = fileName + values.Extension
			}

			// output to stdout only if explicitly asked and never for encryptor output
			t.ToStdout = options.outStd && !t.ProcEnc
			// keeping the input file only if explicitly asked and not if writing to stdout
			t.RemoveInput = !options.filesKeep && !t.ToStdout

			if !t.ToStdout {
				if err = file.MustNotExist(t.OutputFile); err != nil {
					return
				}
			}

			tasks[i] = t
		}

		return
	}()
	if err != nil {
		log.Fatalf("Input file error: %s", err.Error())
		return
	}

	_ = needEncryptor
	_ = needDecryptor

	// Phase: Ask for password and create cipher block

	block, err := func() (block cipher.Block, err error) {
		var key []byte

		if !options.keyUseEmpty {
			key, err = password.Input(needEncryptor && !options.keyAllowWeak, needEncryptor && options.keyRaw == "")
			if err != nil {
				return nil, err
			}
		}

		if len(key) == 0 && !options.keyNoWarn && needEncryptor {
			log.Println("Warning: Using empty key phrase.")
		}

		block, err = processor.CipherBlock(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create cipher block: %w", err)
		}

		return block, nil
	}()
	if err != nil {
		log.Fatalf("Key phrase error: %s", err.Error())
		return
	}

	// Phase: Process each input file

	sort.Slice(tasks, func(i, j int) bool {
		return tasks[i].InputFile < tasks[j].InputFile
	})

	p := printer.MakePrinter(options.outQuiet, options.outNoColor)

	func() {
		var wIn, wOut int
		for _, t := range tasks {
			wIn = max(wIn, len(t.InputFile))
			wOut = max(wOut, len(t.OutputFile))
		}

		p.SetWidths(wIn, wOut)
	}()

	var (
		countDone int
		countFail int
	)

	for _, t := range tasks {
		p.PrintTask(&t)

		if t.ProcEnc {
			err = processor.EncryptFile(hg.ID, block, t.InputFile, t.OutputFile)
		} else if t.ToStdout {
			err = processor.DecryptToStdOut(block, t.InputFile)
		} else {
			err = processor.DecryptToFile(block, t.InputFile, t.OutputFile)
		}
		if err != nil {
			p.PrintFail()
			p.PrintError(err, "Failed to process")

			if !t.ToStdout {
				err = os.Remove(t.OutputFile)
				if err != nil && !os.IsNotExist(err) {
					p.PrintError(err, "Failed to delete failed output %s", t.OutputFile)
				}
			}

			countFail++

			p.PrintLn()
			continue
		}

		countDone++
		p.PrintDone()

		if t.RemoveInput {
			err = os.Remove(t.InputFile)
			if err != nil {
				p.PrintError(err, "Failed to remove input file %s", t.InputFile)
			}
		}

		p.PrintLn()
	}

	var exitCode int

	if countFail > 0 {
		exitCode++
	}

	if countDone == 0 {
		exitCode++
	}

	os.Exit(exitCode)
}
