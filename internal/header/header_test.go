package header

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/rand"
	"testing"

	"github.com/marko-gacesa/fenc/internal/values"
)

func TestHeader(t *testing.T) {
	var iv [aes.BlockSize]byte
	_, err := rand.Read(iv[:])
	if err != nil {
		panic(err)
	}

	raw, hashSum := func() (raw, hashSum []byte) {
		h := New(uint(crypto.MD5), iv[:])

		hasher := h.Hash()
		_, _ = hasher.Write([]byte("12345678"))
		hashSum = hasher.Sum(nil)
		h.SetHashSum(hashSum)

		buffer := bytes.NewBuffer(nil)
		_ = h.Write(buffer)

		raw = buffer.Bytes()

		return
	}()

	h, err := Read(bytes.NewReader(raw))
	if err != nil {
		t.Errorf("failed with error: %v", err)
		return
	}

	if got, want := h.GetVersion(), uint16(values.Version); got != want {
		t.Errorf("version mismatch: got=%d want=%d", got, want)
	}

	if got, want := h.GetHashSum(), hashSum; !bytes.Equal(got, want) {
		t.Errorf("hash sum mismatch: got=%x want=%x", got, want)
	}

	if got, want := h.GetIV(), iv[:]; !bytes.Equal(got, want) {
		t.Errorf("iv mismatch: got=%x want=%x", got, want)
	}
}
