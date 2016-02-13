package password

import (
	"net/http"

	"github.com/boltdb/bolt"
	"github.com/garyburd/redigo/redis"
	"github.com/gorilla/sessions"
)

var sessionStore = sessions.NewCookieStore(genRandBytes())

// Session represents a single session on the server.
type Session struct{}

// SessionStore stores sessions in DBs
type SessionStore interface {
	Get()
	New(r *http.Request)
	Save()
}

// BoltSession is the session DB for Bolt.
type BoltSession struct {
	DB         *bolt.DB
	BucketName []byte
}

func (s *BoltSession) Get()                {}
func (s *BoltSession) New(r *http.Request) {}
func (s *BoltSession) Save()               {}

// RedisSession is the session DB for Redis.
type RedisSession struct {
	DB redis.Conn
}

func (s *RedisSession) Get()                {}
func (s *RedisSession) New(r *http.Request) {}
func (s *RedisSession) Save()               {}
