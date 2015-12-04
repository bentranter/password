package password

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"
)

var (
	signingKey = genRandBytes()

	// ErrInvalidSigningMethod is the error returned when a token's signature
	// does match the signature used to sign the token header.
	ErrInvalidSigningMethod = errors.New("Invalid signing method")
)

// Credentials is the username password thing
type Credentials struct {
	ID     string
	Secret string
}

// Authenticator is an interface for storing and retrieving hashed passwords
type Authenticator interface {
	New() *Credentials
	Store(hashedPassword string) (string, error)
	Retrieve() (string, error)
}

// New hashes and salts a plaintext password using the bcrypt algorithm, and
// stores it. The returned string is the generated key used to identify that
// id/secret combination. For example, it could be the primary key for that
// user in the database.
func New(a Authenticator) (string, error) {
	credentials := a.New()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(credentials.Secret), bcrypt.DefaultCost)
	if err != nil {
		return "", err // couldn't run bcrypt
	}

	id, err := a.Store(string(hashedPassword))
	if err != nil {
		return "", err // couldn't store pwd in db
	}

	return id, nil
}

// Compare compares the stored hashed password with the password provided by
// the user. If they match, it returns a JSON web token.
func Compare(a Authenticator) (string, error) {
	credentials := a.New()
	hashedPassword, err := a.Retrieve()
	if err != nil {
		return "", err // failed to retrieve password
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(credentials.Secret))
	if err != nil {
		return "", err // passwords didn't match
	}

	return genToken(credentials.ID)
}

// Authenticate runs `Compare` against an authenticator interface, and responds
// with a JSON web token in the body of the request.
func Authenticate(w http.ResponseWriter, a Authenticator) {
	tokStr, err := Compare(a)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"token": tokStr})
}

// Protected is middleware that checks to see if the incoming request has a
// valid JSON web token. If it does, it executes the next `http.HandlerFunc`,
// and passes it a `context.Context`
type Protected func(ctx context.Context, w http.ResponseWriter, r *http.Request)

func (fn Protected) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tok, err := jwt.ParseFromRequest(r, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if ok == false {
			return nil, ErrInvalidSigningMethod
		}
		return signingKey, nil
	})
	if err != nil {
		// might wanna use switch statement
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	id := tok.Claims["sub"]
	ctx := context.WithValue(context.Background(), "id", id)

	fn(ctx, w, r)
}

// SetSigningKey allows you to override the default HMAC signing key with one
// of your own. Every time this package is imported, a signing key is set
// randomly. That means that in between restarts, a new key is set, so you'd
// no longer be able to verify JSON web tokens created with that key. In order
// to reuse the signing key, you must set it yourself. Just call this function
// before creating any tokens, and you'll be good to go.
func SetSigningKey(key []byte) {
	signingKey = key
}

func genToken(id string) (string, error) {
	jwt := jwt.New(jwt.SigningMethodHS256)
	expTime := time.Now().Add(time.Hour * 72).Unix()

	jwt.Claims["sub"] = id
	jwt.Claims["exp"] = expTime
	jwt.Claims["iat"] = time.Now().Unix()

	tokStr, err := jwt.SignedString(signingKey)
	if err != nil {
		return "", err // failed to sign token
	}

	return tokStr, nil
}

func genRandBytes() []byte {
	// Use 32 bytes (256 bits) to satisfy the requirement for the HMAC key
	// length.
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		// If this errors, it means that something is wrong the system's
		// CSPRNG, which indicates a critical operating system failure. Panic
		// and crash here
		panic(err)
	}
	return b
}
