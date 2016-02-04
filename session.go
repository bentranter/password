package password

import (
	"net/http"

	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore(genRandBytes())

// GetSession gets the currently active session from the store based on the
// value from the requests cookie.
func GetSession(r *http.Request) {

}

// AuthorizeSession sets the session.
func AuthorizeSession(r *http.Request) {

}
