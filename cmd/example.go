package main

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/bentranter/password"
	"golang.org/x/net/context"
)

type user struct {
	Username string
	Password string
}

func createUser(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	r.ParseForm()
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
