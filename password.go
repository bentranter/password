package password

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/boltdb/bolt"
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

	// Defaults
	// @TODO: Refactor into one struct
	signingKey   = genRandBytes()
	cost         = bcrypt.DefaultCost
	defaultStore = newDB()
)

// Authenticator is the interface that implements the methods for storing and
// retrieving passwords.
type Authenticator interface {
	Store(id string, secret string) (string, error)
	Retrieve(id string, secret string) (string, error)
}

// DefaultStore contains a reference to the default store for Password, and
// satiesfies the Authenticator interface.
type DefaultStore struct {
	DB         *bolt.DB
	BucketName string
	Bucket     *bolt.Bucket
}

// Store stores the given id and secret in Bolt. It will hash the secret using
// bcrypt before storing it.
func (s *DefaultStore) Store(id string, secret string) (string, error) {
	err := s.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(s.BucketName))
		hashedSecret, err := Hash(secret)
		if err != nil {
			return err
		}
		err = b.Put([]byte(id), []byte(hashedSecret))
		return err
	})
	return id, err
}

// Retrieve retrieves the given id and secret from Bolt. It will compare the
// plaintext password with the hashed password.
//
// @TODO: If the majority of DB drivers use byte slices in their drivers,
// switch to that. I should look at mgo, redis, gorethink, and the sql ones.
func (s *DefaultStore) Retrieve(id string, secret string) (string, error) {
	var hashedSecret []byte
	err := s.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(s.BucketName))
		hashedSecret = b.Get([]byte(id))
		return nil
	})
	if err != nil {
		return id, err
	}
	return string(hashedSecret), err
}

func newDB() *DefaultStore {
	db, err := bolt.Open("password.db", 0600, &bolt.Options{
		Timeout: 1 * time.Second,
	})
	if err != nil {
		panic(err)
	}

	var bucket *bolt.Bucket
	bucketName := "Users"
	db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return err
		}
		bucket = b
		return nil
	})

	return &DefaultStore{
		DB:         db,
		Bucket:     bucket,
		BucketName: bucketName,
	}
}

// Hash hashes and salts a plaintext secret using bcrypt.
func Hash(secret string) (string, error) {
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(secret), cost)
	if err != nil {
		return "", err // couldn't run bcrypt
	}
	return string(hashedSecret), nil
}

// Compare compares a hashed secret with a plaintext secret to see if they
// match. If they do, a JSON web token is generated with the given id.
func Compare(id string, secret string, hashedSecret string) (string, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hashedSecret), []byte(secret))
	if err != nil {
		return "", err // passwords didn't match
	}
	return genToken(id)
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
	if err != nil {
		// might wanna use switch statement
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if tok.Valid != true {
		http.Error(w, ErrTokenInvalid.Error(), http.StatusUnauthorized)
	}

	id := tok.Claims["sub"]
	ctx := context.WithValue(context.Background(), "id", id)

	fn(ctx, w, r)
}

// NewUser creates a new user from a username/password combo
func NewUser(id string, secret string) (string, error) {
	id, err := defaultStore.Store(id, secret)
	return id, err
}

// NewAuthenticatedUser creates a new user from a username/password combo, and
// generates a JSON web token. It writes the token in the body of the response
// as JSON.
func NewAuthenticatedUser(w http.ResponseWriter, id string, secret string) {
	id, err := defaultStore.Store(id, secret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	tok, err := genToken(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(map[string]string{"token": tok})
}

// NewCookieAuthenticatedUser is just like NewAuthenticatedUser, but it
// sets a cookie on the response containing the JSON web token (instead of
// responding with the cookie in the body). It will not send the response!
func NewCookieAuthenticatedUser(w http.ResponseWriter, id string, secret string) {
	id, err := defaultStore.Store(id, secret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	tok, err := genToken(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	cookie := &http.Cookie{
		Name:       "user-cookie",
		Value:      tok,
		Path:       "/",
		RawExpires: string(time.Now().Add(time.Hour * 72).Unix()),
		HttpOnly:   true,
	}
	http.SetCookie(w, cookie)
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
	return []byte(base64.URLEncoding.EncodeToString(b))
}
