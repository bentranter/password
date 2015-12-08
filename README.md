Password [![GoDoc](https://godoc.org/github.com/bentranter/password?status.svg)](https://godoc.org/github.com/bentranter/password)
===

Dead simple username/password based auth for web apps.

Installation
---

```bash
$ go get github.com/bentranter
```

Intro
---

**Password** provides a simple, JSON web token based authentication solution for web apps. When a user signs in to your web app, they'll receive a JSON web token in the response body. To access protected resources, they must send that token with the request.

Here is the most basic example:

```go
package main

import (
	"net/http"

	"github.com/bentranter/password"
	"golang.org/x/net/context"
)

func SignUp(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("Username")
	password := r.FormValue("Password")

	id, err := password.New(username, password, UserStore)
	w.Write([]byte(id))
}

func SignIn(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("Username")
	password := r.FormValue("Password")

	password.Authenticate(username, password, w, UserStore)
}

func WhoAmI(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	username := ctx.Value("id")
	w.Write([]byte(username))
}

func main() {
	http.HandleFunc("/signup", SignUp)
	http.HandleFunc("/signin", SignIn)
	http.Handle("/protected", password.Protected(WhoAmI))
}
```

Usage
---

In the above example, you can see a reference to a UserStore. In order to use Password, you'll need to create your own user store. Don't worry though! `UserStore` is simply a struct that satisfies the `password.Authenticator` interface. That interface only has two methods:

- `Store(id string, hashedPassword string) (string, error)`
- `Retrieve(id string) (string, error)`

The `Store` method should create a new entry in your data store with the given `id` (which could be the user's username, user id, whatever is used to match them to their password) and `hashedPassword`. The `hashedPassword` is the user's password that has been hashed and salted using Go's bcrypt implementation. The `Store` method should return the `id`.

The `Retrieve` method is used to compare passwords, so the method needs to find the user in the data store by their `id`, and return their hashed password.

To see a fully functional but very simple example of this, try out the program in the [cmd](https://github.com/bentranter/password/tree/master/cmd) folder of this repo.

License
---

Password is licensed under the Apache v2.0 license. See the license file for more information.
