package password

import (
	"time"

	"github.com/boltdb/bolt"
	"github.com/garyburd/redigo/redis"
	"golang.org/x/crypto/bcrypt"
)

var userStore = NewBoltUserStore()

// User represents a single user
type User struct {
	ID          []byte
	Password    []byte
	Name        []byte
	Email       []byte
	DateCreated time.Time
	LastLogin   time.Time
	PhoneNumber []byte
}

// UserStore stores users in DBs
type UserStore interface {
	All() []*User
	Create(u *User) ([]byte, error)
	Find(id []byte) *User
	Update(id []byte) error
	Delete(id []byte) error
}

// BoltUser is the user DB for Bolt.
type BoltUser struct {
	DB         *bolt.DB
	BucketName []byte
}

func (b *BoltUser) All() {}

// Create creates a new user in the DB
func (b *BoltUser) Create(u *User) ([]byte, error) {
	err := b.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(b.BucketName)
		hashedSecret, err := bcrypt.GenerateFromPassword(u.Password, bcrypt.DefaultCost)
		u.Password = hashedSecret
		if err != nil {
			return err
		}
		err = b.Put(u.Email, hashedSecret)
		return err
	})
	return u.ID, err
}

func (b *BoltUser) Find()   {}
func (b *BoltUser) Update() {}
func (b *BoltUser) Delete() {}

// RedisUser is the user DB for Redis.
type RedisUser struct {
	DB redis.Conn
}

func (u *RedisUser) All()    {}
func (u *RedisUser) Create() {}
func (u *RedisUser) Find()   {}
func (u *RedisUser) Update() {}
func (u *RedisUser) Delete() {}

// NewBoltUserStore creates a new instance of BoltUser.
func NewBoltUserStore() *BoltUser {
	db, err := bolt.Open("boltuser.db", 0600, &bolt.Options{
		Timeout: 1 * time.Second,
	})
	if err != nil {
		panic(err)
	}

	db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("boltuserbucket"))
		if err != nil {
			return err
		}
		return nil
	})

	return &BoltUser{
		DB:         db,
		BucketName: []byte("boltuserbucket"),
	}
}
