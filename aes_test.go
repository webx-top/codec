package codec

import (
	"fmt"
	"testing"
	"time"
)

func TestAes(t *testing.T) {
	var (
		paykey = fmt.Sprintf(`%032d`, time.Now().UnixMicro())
	)

	crypto := NewAES(`AES-256-ECB`)
	plaintext := `admpub.com`
	crypted := crypto.Encode(plaintext, paykey)
	if crypto.Decode(crypted, paykey) != plaintext {
		t.Fatal(`failed`)
	}
	//t.Fatal(crypto.Decode(crypted, paykey))
}
