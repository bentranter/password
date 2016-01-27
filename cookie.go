package password

import (
	"net/http"
	"time"
)

// ExpireCookie sets the expiry on the cookie. It will not send the request.
func ExpireCookie(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("user")
	cookie.Value = ""
	cookie.RawExpires = string(time.UnixDate)
	cookie.MaxAge = -1
	http.SetCookie(w, cookie)
}
