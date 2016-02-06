package password

import (
	"github.com/boltdb/bolt"
	"github.com/garyburd/redigo/redis"
)

var userStore = ""

// UserStore stores users in DBs
type UserStore interface {
	All()
	Create()
	Find()
	Update()
	Delete()
}

// BoltUser is the user DB for Bolt.
type BoltUser struct {
	DB         *bolt.DB
	BucketName []byte
}

func (u *BoltUser) All()    {}
func (u *BoltUser) Create() {}
func (u *BoltUser) Find()   {}
func (u *BoltUser) Update() {}
func (u *BoltUser) Delete() {}

// RedisUser is the user DB for Redis.
type RedisUser struct {
	DB redis.Conn
}

func (u *RedisUser) All()    {}
func (u *RedisUser) Create() {}
func (u *RedisUser) Find()   {}
func (u *RedisUser) Update() {}
func (u *RedisUser) Delete() {}
