package password

import "testing"

func Test_GenToken(t *testing.T) {
	_, err := GenToken("1")
	if err != nil {
		t.Errorf("Failed: Error whle genrating token. %s\n", err.Error())
	}
}

func Test_genRandBytes(t *testing.T) {
	l := len(genRandBytes())
	if l != 32 {
		t.Errorf("Failed: Expected 32 bytes to be generated, got %d\n", l)
	}
}
