package codec

import (
	"testing"

	"github.com/webx-top/com"
)

func TestAes(t *testing.T) {
	var (
		paykey = com.RandomString(32)
	)

	crypto := NewAesCrypto(`AES-256-ECB`)
	plaintext := `admpub.com`
	crypted := crypto.Encode(plaintext, paykey)
	if crypto.Decode(crypted, paykey) != plaintext {
		t.Fatal(`failed`)
	}
	//t.Fatal(crypto.Decode(crypted, paykey))
}
