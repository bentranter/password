/*
Package password implements a simple JSON web token based authentication
system. It uses BoltDB as a default store for user information.


Background

The package revolves around the password.Authenticator interface. This
interface implements only two methods: one for storing passwords, and one for
retrieving them. This lets you use any backend to store your users, whether
that be an in-memory store, Redis, Postgres, or something else altogether.


Usage

The functions defined in this library are designed to make it as easy as
possible to create and authenticate users. They are all designed to be used
with HTTP handlers:

	// Grab the username and password from the request, and create a new user
	// in the user store with those values
	http.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("Username")
		password := r.FormValue("Password")
		id, _ := password.New(username, password, UserStore)
		w.Write([]byte("New user: "+id))
	})
	...
	// Sign in using a username and password. This will respond with a JSON web
	// token if the user authenticates successfully
	http.HandleFunc("/signin", func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("Username")
		password := r.FormValue("Password")
		password.Authenticate(username, password, w, UserStore)
	})
	...
	// Respond with the user's username. If they don't have a valid JSON web
	// token, then this request will fail, saying the client is unauthorized
	http.Handle("/whoami", password.Protected(
		func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
			username := ctx.Value("id")
			fmt.Fprintf(w, "Your username: %s\n", username)
	}))

In this example, "UserStore" would satisfy the password.Authenticator
interface. For a reference implementation of this interface, see the example
in the GitHub repository.
*/
package password
