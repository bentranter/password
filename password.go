/*
 * Password is the main API. It implements the HTTP handlers
 */

package password

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"
)

var (
	// ErrInvalidSigningMethod is the error returned when a token's signature
	// does match the signature used to sign the token header.
	ErrInvalidSigningMethod = errors.New("Invalid signing method")
	// ErrTokenInvalid means the signature didn't match.
	ErrTokenInvalid = errors.New("Token isn't valid")

	cost = bcrypt.DefaultCost
)

// Authenticator is the interface that implements the methods for storing and
// retrieving passwords.
type Authenticator interface {
	Store(id string, secret string) (string, error)
	Retrieve(id string, secret string) (string, error)
}

// Hash hashes and salts a plaintext secret using bcrypt.
func Hash(secret string) ([]byte, error) {
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(secret), cost)
	if err != nil {
		return nil, err // couldn't run bcrypt
	}
	return hashedSecret, nil
}

// Compare compares a hashed secret with a plaintext secret to see if they
// match. If they do, a JSON web token is generated with the given id.
func Compare(id string, secret string, hashedSecret string) (string, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hashedSecret), []byte(secret))
	if err != nil {
		return "", err // passwords didn't match
	}
	return GenToken(id)
}

// Authenticate runs `Compare`, and writes the generated JSON web token to the
// response writer.
func Authenticate(w http.ResponseWriter, id string, secret string, hashedSecret string) {
	tokStr, err := Compare(id, secret, hashedSecret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"token": tokStr})
}

// Protect is middleware that checks to see if the incoming request has a
// valid JSON web token. If it does, it executes the next `http.HandlerFunc`,
// and passes it a `context.Context` with the field "id" assigned to the
// current user id.
type Protect func(ctx context.Context, w http.ResponseWriter, r *http.Request)

func (fn Protect) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tok, err := jwt.ParseFromRequest(r, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if ok == false {
			return nil, ErrInvalidSigningMethod
		}
		return signingKey, nil
	})

	switch err {
	case jwt.ErrNoTokenInRequest:
		// User isn't logged in - don't want to error
		ctx := context.WithValue(context.Background(), "id", nil)
		fn(ctx, w, r)
	case nil:
		if tok.Valid != true {
			http.Error(w, ErrTokenInvalid.Error(), http.StatusUnauthorized)
			return
		}

		id := tok.Claims["sub"]
		ctx := context.WithValue(context.Background(), "id", id)

		fn(ctx, w, r)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// CookieProtect is the same as `Protect`, but it looks for the token in the
// `user-cookie` instead of the Authorization header. It's meant to be used
// with the `NewCookieAuthenticatedUser` function.
type CookieProtect func(ctx context.Context, w http.ResponseWriter, r *http.Request)

func (fn CookieProtect) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("user")
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	tok, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if ok == false {
			return nil, ErrInvalidSigningMethod
		}
		return signingKey, nil
	})

	if err != nil {
		// might wanna use switch statement
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if tok.Valid != true {
		http.Error(w, ErrTokenInvalid.Error(), http.StatusUnauthorized)
		return
	}

	// Get the user id from the token
	id := tok.Claims["sub"]
	ctx := context.WithValue(context.Background(), "id", id)

	// Execute the handler with the user in the context
	fn(ctx, w, r)

}

// CreateUser creates a new user from a username/password combo
func CreateUser(id string, secret string) (string, error) {
	id, err := DefaultStore.Store(id, secret)
	return id, err
}

// NewAuthenticatedUser creates a new user from a username/password combo, and
// generates a JSON web token. It writes the token in the body of the response
// as JSON.
func NewAuthenticatedUser(w http.ResponseWriter, id string, secret string) {
	id, err := DefaultStore.Store(id, secret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tok, err := GenToken(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"token": tok})
}

// NewCookieAuthenticatedUser is just like NewAuthenticatedUser, but it
// sets a cookie on the response containing the JSON web token (instead of
// responding with the cookie in the body). It will not send the response!
func NewCookieAuthenticatedUser(w http.ResponseWriter, id string, secret string) {
	id, err := DefaultStore.Store(id, secret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tok, err := GenToken(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cookie := &http.Cookie{
		Name:       "user",
		Value:      tok,
		Path:       "/",
		RawExpires: string(time.Now().Add(time.Hour * 72).Unix()),
		HttpOnly:   true,
	}
	http.SetCookie(w, cookie)
}
