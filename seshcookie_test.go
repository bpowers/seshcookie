package seshcookie

import (
	"time"
	"crypto/sha1"
	"testing"
)

func createKey() (key, iv []byte) {
	keySha1 := sha1.New()
	keySha1.Write([]byte(time.UTC().String()))
	keyBytes := keySha1.Sum()
	return keyBytes[:16], keyBytes[4:]
}

func TestRoundtrip(t *testing.T) {
	key, iv := createKey()

	orig := map[string]interface{}{"a": 1, "b": "c", "d": 1.2}

	encoded, err := encodeCookie(orig, key, iv)
	if err != nil {
		t.Errorf("encodeCookie: %s", err)
		return
	}
	decoded, err := decodeCookie(encoded, key, iv)
	if err != nil {
		t.Errorf("decodeCookie: %s", err)
		return
	}

	if decoded == nil {
		t.Errorf("decoded map is null")
		return
	}

	if len(decoded) != 3 {
		t.Errorf("len was %d, expected 3", len(decoded))
		return
	}

	for k, v := range orig {
		if decoded[k] != v {
			t.Errorf("expected decoded[%s] (%#v) == %#v", k,
				decoded[k], v)
		}
	}
}
