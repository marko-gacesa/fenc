package processor

import (
	"strings"
	"testing"
)

func TestCipherBlock(t *testing.T) {
	const text = "0123456789abcdef"
	const n = 33
	m := map[int][]byte{}
	for l := range n {
		s := strings.Repeat("a", l)
		b, err := CipherBlock([]byte(s))
		if err != nil {
			t.Errorf("got error for len=%d: %s", l, err.Error())
			return
		}
		enc := make([]byte, len(text))
		b.Encrypt(enc, []byte(text))
		m[l] = enc
	}
	for l := range n {
		s := strings.Repeat("a", l)
		b, _ := CipherBlock([]byte(s))
		dec := make([]byte, len(text))
		b.Decrypt(dec, m[l])
		if text != string(dec) {
			t.Errorf("not equal for len=%d text=%s", l, dec)
		}
	}
}
