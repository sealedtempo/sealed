package hexb

import "testing"

func TestDecode(t *testing.T) {
	for _, s := range []string{"0xABcd", "abcd", "0XabCD"} {
		b, err := Decode(s, 2)
		if err != nil || b[0] != 0xab || b[1] != 0xcd {
			t.Fatalf("Decode(%q) = %x, %v", s, b, err)
		}
	}
	for _, s := range []string{"0xabc", "zz", "0xabcd00"} {
		if _, err := Decode(s, 2); err == nil {
			t.Fatalf("Decode(%q) accepted", s)
		}
	}
	if b, err := Decode("0x", -1); err != nil || len(b) != 0 {
		t.Fatal("empty hex with any length")
	}
	if _, err := Decode32("0x" + "00"); err == nil {
		t.Fatal("short 32-byte value accepted")
	}
	if _, err := Decode20("0x" + "11111111111111111111111111111111111111"); err == nil {
		t.Fatal("19-byte address accepted")
	}
	if Enc([]byte{0xab, 0x01}) != "0xab01" {
		t.Fatal("Enc")
	}
}
