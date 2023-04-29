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

	GenAESKey([]byte(`2`))
}

func TestGenAESKey(t *testing.T) {
	key := GenAESKey([]byte(`2`))
	t.Logf(`key: [%s]`, key)
	if string(key) != `               2` {
		t.Fatal(`failed`)
	}

	key = GenAESKey([]byte(`123`))
	t.Logf(`key: [%s]`, key)
	if string(key) != `             123` {
		t.Fatal(`failed`)
	}

	key = GenAESKey([]byte(``))
	t.Logf(`key: [%s]`, key)
	if string(key) != `                ` {
		t.Fatal(`failed`)
	}

	key = GenAESKey([]byte(`12345678901234567890`))
	t.Logf(`key: [%s]`, key)
	if string(key) != `1234567890123456` {
		t.Fatal(`failed`)
	}
}
