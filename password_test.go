package password

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/net/context"
)

var (
	key = []byte("secret")
)

type tokStruct struct {
	Token string `json:"token"`
}

func TestHash(t *testing.T) {
	// We need to set the signing key at the beginning of the tests, so that we
	// can re-use it later to decode tokens
	SetSigningKey(key)
	hashedSecret, err := Hash(u.Username, u.Password)

	if err != nil {
		t.Errorf("Failed to hash secret: %s\n", err.Error())
	}
	if hashedSecret == u.Password {
		t.Errorf("Password not hashed: %s %s\n", hashedSecret, u.Password)
	}
}

func TestCompare(t *testing.T) {
	tokStr, err := Compare(u.Username, u.Password, storedPassword)

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
	if token.Claims["sub"] != u.Username {
		t.Errorf("Incorrect claims for sub field: %s\n", token.Claims["sub"])
	}
}

func TestAuthenticate(t *testing.T) {
	w := httptest.NewRecorder()

	Authenticate(w, u.Username, u.Password, storedPassword)
	body, err := ioutil.ReadAll(w.Body)

	if err != nil {
		t.Errorf("Couldn't read recorded response body: %s\n", err)
	}
	if len(body) == 0 {
		t.Errorf("Response body is an empty string")
	}

	tokJSON = fmt.Sprintf("%s\n", body)
}

func TestProtect(t *testing.T) {
	ts := httptest.NewServer(Protect(authReq))
	defer ts.Close()

	client := &http.Client{}
	req, err := http.NewRequest("POST", ts.URL, nil)
	if err != nil {
		t.Errorf("Couldn't create new test request: %s\n", err)
	}

	var tok tokStruct
	json.Unmarshal([]byte(tokJSON), &tok)
	req.Header.Set("Authorization", "Bearer "+tok.Token)

	res, err := client.Do(req)
	if err != nil {
		t.Errorf("Failed to complete mocked POST request: %s\n", err)
	}
	res.Body.Close()

	status := res.StatusCode
	if status != 200 {
		t.Errorf("Expected response status to be 200, got %d\n", status)
	}
}

func authReq(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value("id")
	w.Write([]byte("User: " + user.(string)))
}
