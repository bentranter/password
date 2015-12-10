package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/bentranter/password"
	"golang.org/x/net/context"
)

var (
	db = newInMemDB()
)

type inMemDB struct {
	rwm *sync.RWMutex
	m   map[string]string
}

func newInMemDB() *inMemDB {
	return &inMemDB{
		rwm: &sync.RWMutex{},
		m:   make(map[string]string),
	}
}

func (db *inMemDB) Store(id string, hashedPassword string) (string, error) {
	db.rwm.Lock()
	defer db.rwm.Unlock()
	key := genKey()
	db.m[key] = hashedPassword
	return key, nil
}

func (db *inMemDB) Retrieve(id string) (string, error) {
	db.rwm.RLock()
	defer db.rwm.RUnlock()
	return db.m[id], nil
}

type user struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func createUser(w http.ResponseWriter, r *http.Request) {
	var u user
	json.NewDecoder(r.Body).Decode(&u)

	id, err := password.New(u.Username, u.Password, db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "{\n\tid: %s\n}\n", id)
}

func comparePwd(w http.ResponseWriter, r *http.Request) {
	var u user
	json.NewDecoder(r.Body).Decode(&u)
	password.Authenticate(u.Username, u.Password, w, db)
}

func authReq(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value("id")
	w.Write([]byte("User: " + user.(string)))
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", createUser)
	mux.HandleFunc("/auth", comparePwd)
	mux.Handle("/user", password.Protect(authReq))

	http.ListenAndServe(":3000", mux)
}

func genKey() string {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
