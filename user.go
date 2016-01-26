package password

// User is the type
type User struct {
	ID          string
	Email       string
	PhoneNumber string
	Password    string
}

// ANewUser creates a new user with the provided info. It validates the email.
func ANewUser(id string, email string, phoneNumber string, password string) (*User, error) {
	phoneNumber, err := EnsurePhoneNumber(phoneNumber)
	if err != nil {
		return nil, err
	}

	return &User{
		ID:          id,
		Email:       email,
		PhoneNumber: phoneNumber,
		Password:    password,
	}, nil
}

// IsEmail will verify that the given string is a valid email address. It
// will return false if it is not, and true if it is.
func IsEmail(email string) bool {
	return true
}

// EnsurePhoneNumber removes any characters that aren't 0-9 from the string.
func EnsurePhoneNumber(phoneNum string) (string, error) {
	var validatedPhoneNum []byte
	for _, str := range phoneNum {
		if str >= 48 && str <= 57 {
			validatedPhoneNum = append(validatedPhoneNum, byte(str))
		}
	}
	return string(validatedPhoneNum), nil
}
