package codec

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

func TestAES(t *testing.T) {
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

func TestFixedKeyDefault(t *testing.T) {
	pwd := `123`
	key := Md5bytes([]byte(pwd))
	key2 := Md5str(pwd)
	if string(key) != key2 {
		t.Fatalf(`%s != %s`, key, key2)
	}
	t.Logf(`md5key: %s`, key)
	fixedKey := FixedKeyDefault(16, key)
	t.Logf(`fixedKey: %s`, hex.EncodeToString(fixedKey))

	pwd = `1234`
	key = Md5bytes([]byte(pwd))
	t.Logf(`md5key: %s`, key)
	fixedKey = FixedKeyDefault(16, key)
	t.Logf(`fixedKey: %s`, hex.EncodeToString(fixedKey))
}

func TestGenAESKey(t *testing.T) {
	aesKey := newAESKey(KeyAES128)
	aesKey.SetKeyFixer(FixedKeyByWhitespacePrefix)
	key := aesKey.GenKey([]byte(`2`))
	t.Logf(`key: [%s]`, key)
	if string(key) != `               2` {
		t.Fatal(`failed`)
	}

	key = aesKey.GenKey([]byte(`123`))
	t.Logf(`key: [%s]`, key)
	if string(key) != `             123` {
		t.Fatal(`failed`)
	}

	key = aesKey.GenKey([]byte(``))
	t.Logf(`key: [%s]`, key)
	if string(key) != `                ` {
		t.Fatal(`failed`)
	}

	key = aesKey.GenKey([]byte(`12345678901234567890`))
	t.Logf(`key: [%s]`, key)
	if string(key) != `1234567890123456` {
		t.Fatal(`failed`)
	}
}
