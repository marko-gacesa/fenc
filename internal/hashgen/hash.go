package hashgen

import (
	"crypto"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

type HashGen struct {
	ID   uint
	Name string
	Gen  func() hash.Hash
}

var ErrorUnsupportedHashFn = errors.New("unsupported hash function")

func FromName(name string) (h HashGen, err error) {
	switch name {
	case "md5":
		h = HashGen{ID: uint(crypto.MD5), Name: name, Gen: md5.New}
	case "sha1":
		h = HashGen{ID: uint(crypto.SHA1), Name: name, Gen: sha1.New}
	case "sha256":
		h = HashGen{ID: uint(crypto.SHA256), Name: name, Gen: sha256.New}
	case "sha512":
		h = HashGen{ID: uint(crypto.SHA512), Name: name, Gen: sha512.New}
	default:
		err = ErrorUnsupportedHashFn
	}

	return
}

func FromID(id uint) (h HashGen, err error) {
	switch crypto.Hash(id) {
	case crypto.MD5:
		h = HashGen{ID: id, Name: "md5", Gen: md5.New}
	case crypto.SHA1:
		h = HashGen{ID: id, Name: "sha1", Gen: sha1.New}
	case crypto.SHA256:
		h = HashGen{ID: id, Name: "sha256", Gen: sha256.New}
	case crypto.SHA512:
		h = HashGen{ID: id, Name: "sha512", Gen: sha512.New}
	default:
		err = ErrorUnsupportedHashFn
	}

	return
}
