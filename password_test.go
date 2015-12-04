package password

import (
	"fmt"
	"io/ioutil"
	"net/http/httptest"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
)

var (
	storedPassword = ""
	key            = []byte("The quick brown fox jumps over the lazy dog")
	tokJSON        = ""
)

type tokStruct struct {
	token string
}

type mock struct {
	username string
	password string
}

func (m *mock) New() *Credentials {
	return &Credentials{
		ID:     m.username,
		Secret: m.password,
	}
}

func (m *mock) Store(hashedPassword string) (string, error) {
	storedPassword = hashedPassword
	return "1", nil
}

func (m *mock) Retrieve() (string, error) {
	return storedPassword, nil
}

func TestNew(t *testing.T) {
	// We need to set the signing key at the beginning of the tests, so that we
	// can re-use it later to decode tokens
	SetSigningKey(key)

	m := &mock{
		username: "Tester",
		password: "password",
	}
	New(m)

	if m.password == storedPassword {
		t.Errorf("Password hashing failed")
	}
}

func TestCompare(t *testing.T) {
	m := &mock{
		username: "Tester",
		password: "password",
	}
	tokStr, err := Compare(m)

	if err != nil {
		t.Errorf("Comparing passwords failed with error: %s\n", err)
	}
	if len(tokStr) == 0 {
		t.Errorf("No token")
	}

	token, err := jwt.Parse(tokStr, func(tok *jwt.Token) (interface{}, error) {
		return key, nil
	})
	if err != nil {
		t.Errorf("Couldn't parse token: %s\n", err)
	}
	if token.Claims["sub"] != "Tester" {
		t.Errorf("Incorrect claims for sub field: %s\n", token.Claims["sub"])
	}
}

func TestAuthenticate(t *testing.T) {
	m := &mock{
		username: "Tester",
		password: "password",
	}
	w := httptest.NewRecorder()

	Authenticate(w, m)
	body, err := ioutil.ReadAll(w.Body)

	if err != nil {
		t.Errorf("Couldn't read recorded response body")
	}
	if len(body) == 0 {
		t.Errorf("Response body is an empty string")
	}

	tokJSON = fmt.Sprintf("%s\n", body)
}

func TestProtected(t *testing.T) {

}
