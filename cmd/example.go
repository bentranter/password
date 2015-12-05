package main

import (
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
	m   map[int]string
}

func newInMemDB() *inMemDB {
	return &inMemDB{
		rwm: &sync.RWMutex{},
		m:   make(map[int]string),
	}
}

func (db *inMemDB) Store(hashedPassword string) (string, error) {
	db.rwm.Lock()
	defer db.rwm.Unlock()
	db.m[1] = hashedPassword
	return "1", nil
}

func (db *inMemDB) Retrieve(id string) (string, error) {
	db.rwm.RLock()
	defer db.rwm.RUnlock()
	return db.m[1], nil
}

type user struct {
	username string `json:"username"`
	password string `json:"password"`
}

func createUser(w http.ResponseWriter, r *http.Request) {
	var u user
	json.NewDecoder(r.Body).Decode(&u)
	fmt.Printf("User: %+v\n", u)

	id, err := password.New(u.password, db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "{\n\tid: %s\n}\n", id)
}

func comparePwd(w http.ResponseWriter, r *http.Request) {
	var u user
	json.NewDecoder(r.Body).Decode(&u)
	fmt.Printf("User: %+v\n", u)

	password.Authenticate(u.username, u.password, w, db)
}

func authReq(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	user := ctx.Value("id")
	w.Write([]byte("User: " + user.(string)))
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", createUser)
	mux.HandleFunc("/auth", comparePwd)
	mux.Handle("/user", password.Protected(authReq))

	http.ListenAndServe(":3000", mux)
}
