package main

import (
	"net/http"
	"text/template"

	"github.com/bentranter/password"
	"golang.org/x/net/context"
)

const signUpForm = `
<div style="font-family: 'Helvetica', sans-serif; margin: 2rem; color: #333">
	<h3 style="font-size: 1.5rem">Sign Up</h3>
	<form action="/" method="POST">
		<input type="text" name="username" placeholder="Username">
		<input type="password" name="password" placeholder="Password">
		<input type="submit" value="Sign Up">
	</form>
</div>
`

const signedIn = `
	<div style="font-family: 'Helvetica', sans-serif; margin: 2rem; color: #333">
		<h3 style="font-size: 1.5rem">Thanks for signing up!</h3>
		<p>Click <a href="/me">here</a> to see who you are...</p>
	</div>
`

const hello = `
	<div style="font-family: 'Helvetica', sans-serif; margin: 2rem; color: #333">
		<h3 style="font-size: 1.5rem">Hello, {{ .User }}!</h3>
	</div>
`

func createUser(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		t, err := template.New("signUpForm").Parse(signUpForm)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		t.Execute(w, nil)
	case "POST":
		id := r.FormValue("username")
		secret := r.FormValue("password")
		r.ParseForm()

		password.NewCookieAuthenticatedUser(w, id, secret)
		t, err := template.New("signedIn").Parse(signedIn)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		t.Execute(w, nil)
	default:
		http.Error(w, "Use GET or POST", http.StatusMethodNotAllowed)
	}
}

func authReq(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	id := ctx.Value("id")
	user := map[string]string{"User": id.(string)}
	t, err := template.New("hello").Parse(hello)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	t.Execute(w, user)
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", createUser)
	mux.Handle("/me", password.CookieProtect(authReq))

	http.ListenAndServe(":3000", mux)
}
