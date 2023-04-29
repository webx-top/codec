package codec

import (
	"bytes"
	"testing"
)

func TestGenDESKey(t *testing.T) {
	key := GenDESKey([]byte(``))
	t.Logf(`key: [%s]`, key)
	if string(key) != `        ` {
		t.Fatal(`failed`)
	}

	key = GenDESKey([]byte(`123`))
	t.Logf(`key: [%s]`, key)
	if !bytes.Equal(key, []byte(`12312312`)) {
		t.Fatalf(`failed: %s`, key)
	}

	key = GenDESKey([]byte(`12345678901234567890`))
	t.Logf(`key: [%s]`, key)
	if string(key) != `12345678` {
		t.Fatal(`failed`)
	}
}
