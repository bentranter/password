package db

import (
	"time"
)

// User is the type for our user data
type User struct {
	ID          string
	FirstName   string
	LastName    string
	Email       string
	DateCreated time.Time
}
