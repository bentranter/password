package password

import "testing"

func Test_genRandBytes(t *testing.T) {
	l := len(genRandBytes())
	if l != 32 {
		t.Errorf("Failed: Expected 32 bytes to be generated, got %d\n", l)
	}
}
