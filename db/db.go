package db

// UserStore contains the methods implemented by both BoltDB and Redis for
// interacting with our users.
type UserStore interface {
	All()
	Create()
	Find()
	Update()
	Delete()
}

// SessionStore contains the methods implemented by both BoltDB and Redis
// for interacting with our sessions.
type SessionStore interface {
	Get()
	New()
	Save()
}
