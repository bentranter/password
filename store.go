/*
 * Store is the data store
 */

package password

import (
	"time"

	"github.com/boltdb/bolt"
)

// DefaultStore is the default database to store users, sessions, and CSRF
// tokens. It's a single BoltDB instance.
var DefaultStore = newDB()

// Store contains a reference to the default store for Password, and
// satiesfies the Authenticator interface.
type Store struct {
	DB         *bolt.DB
	BucketName string
	Bucket     *bolt.Bucket
}

// Store stores the given id and secret in Bolt. It will hash the secret using
// bcrypt before storing it.
func (s *Store) Store(id string, secret string) (string, error) {
	err := s.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(s.BucketName))
		hashedSecret, err := Hash(secret)
		if err != nil {
			return err
		}
		err = b.Put([]byte(id), []byte(hashedSecret))
		return err
	})
	return id, err
}

// Retrieve retrieves the given id and secret from Bolt. It will compare the
// plaintext password with the hashed password.
//
// @TODO: If the majority of DB drivers use byte slices in their drivers,
// switch to that. I should look at mgo, redis, gorethink, and the sql ones.
func (s *Store) Retrieve(id string, secret string) (string, error) {
	var hashedSecret []byte
	err := s.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(s.BucketName))
		hashedSecret = b.Get([]byte(id))
		return nil
	})
	if err != nil {
		return id, err
	}
	return string(hashedSecret), err
}

func newDB() *Store {
	db, err := bolt.Open("password.db", 0600, &bolt.Options{
		Timeout: 1 * time.Second,
	})
	if err != nil {
		panic(err)
	}

	var bucket *bolt.Bucket
	bucketName := "Users"
	db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return err
		}
		bucket = b
		return nil
	})

	return &Store{
		DB:         db,
		Bucket:     bucket,
		BucketName: bucketName,
	}
}
