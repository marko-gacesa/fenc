package header

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/marko-gacesa/fenc/internal/hashgen"
	"github.com/marko-gacesa/fenc/internal/values"
)

const Size = 128

const (
	fieldSignatureOffset = 0
	fieldSignatureSize   = 4

	fieldVersionOffset = fieldSignatureOffset + fieldSignatureSize
	fieldVersionSize   = 2

	fieldHashIDOffset = fieldVersionOffset + fieldVersionSize
	fieldHashIDSize   = 2

	fieldHashSumOffset = fieldHashIDOffset + fieldHashIDSize
	fieldHashSumSize   = 64 // 64 bytes = 512 bits max size

	fieldIVOffset = fieldHashSumOffset + fieldHashSumSize
	fieldIVSize   = aes.BlockSize

	reservedOffset = fieldIVOffset + fieldIVSize
	reservedSize   = Size - reservedOffset
)

type Header struct {
	version uint16
	hg      hashgen.HashGen
	hashSum []byte
	iv      [aes.BlockSize]byte
}

func New(hashID uint, iv []byte) *Header {
	hg, err := hashgen.FromID(hashID)
	if err != nil {
		panic(err)
	}

	if len(iv) != aes.BlockSize {
		panic("header: invalid iv size")
	}

	h := &Header{
		version: values.Version,
		hg:      hg,
	}

	copy(h.iv[:], iv)

	return h
}

func (h *Header) packRaw(raw *[Size]byte) {
	_, _ = rand.Read(raw[:])
	copy(raw[fieldSignatureOffset:fieldSignatureOffset+fieldSignatureSize], values.Signature)
	binary.LittleEndian.PutUint16(raw[fieldVersionOffset:fieldVersionOffset+fieldVersionSize], h.version)
	binary.LittleEndian.PutUint16(raw[fieldHashIDOffset:fieldHashIDOffset+fieldHashIDSize], uint16(h.hg.ID))
	copy(raw[fieldHashSumOffset:fieldHashSumOffset+len(h.hashSum)], h.hashSum)
	copy(raw[fieldIVOffset:fieldIVOffset+fieldIVSize], h.iv[:])
}

func (h *Header) unpackRaw(raw *[Size]byte) error {
	if string(raw[fieldSignatureOffset:fieldSignatureOffset+fieldSignatureSize]) != values.Signature {
		return errors.New("header: signature mismatch")
	}

	version := binary.LittleEndian.Uint16(raw[fieldVersionOffset : fieldVersionOffset+fieldVersionSize])
	if version > values.Version {
		return errors.New("header: unsupported version")
	}

	hashID := uint(binary.LittleEndian.Uint16(raw[fieldHashIDOffset : fieldHashIDOffset+fieldHashIDSize]))
	hg, err := hashgen.FromID(hashID)
	if err != nil {
		return fmt.Errorf("header: unrecognized hash ID=%d", hashID)
	}

	size := hg.Gen().Size()
	hashSum := raw[fieldHashSumOffset : fieldHashSumOffset+size]

	iv := raw[fieldIVOffset : fieldIVOffset+fieldIVSize]

	h.version = version
	h.hashSum = hashSum
	h.hg = hg
	copy(h.iv[:], iv)

	return nil
}

func (h *Header) Hash() hash.Hash {
	return h.hg.Gen()
}

func (h *Header) SetHashSum(hashSum []byte) {
	if h.hashSum != nil {
		panic("header: hash sum already set")
	}

	if h.hg.Gen().Size() != len(hashSum) {
		panic("header: wrong hash sum size")
	}

	h.hashSum = hashSum
}

func (h *Header) GetVersion() uint16 {
	return h.version
}

func (h *Header) GetHashSum() []byte {
	return h.hashSum
}

func (h *Header) GetIV() []byte {
	return h.iv[:]
}

func (h *Header) Update(w io.WriteSeeker) error {
	_, err := w.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("header: failed to seek file start: %w", err)
	}

	return h.Write(w)
}

func (h *Header) Write(w io.Writer) error {
	var raw [Size]byte
	h.packRaw(&raw)

	_, err := w.Write(raw[:])
	if err != nil {
		err = fmt.Errorf("header: failed to write: %w", err)
		return err
	}

	return err
}

func Read(r io.Reader) (*Header, error) {
	h := &Header{}

	var raw [Size]byte

	n, err := r.Read(raw[:])
	if err != nil {
		return nil, fmt.Errorf("header: failed to read: %w", err)
	}
	if n != Size {
		return nil, fmt.Errorf("header: read %d of %d bytes", n, Size)
	}

	err = h.unpackRaw(&raw)
	if err != nil {
		return nil, err
	}

	return h, nil
}
