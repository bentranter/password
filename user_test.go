package password

import "testing"

func Test_NewUser(t *testing.T) {
	t.Skip()
}

func Test_IsEmail(t *testing.T) {
	t.Skip()
}

func Test_EnsurePhoneNumber(t *testing.T) {
	nums := map[int]string{
		1: "1234567890",
		2: "123-456-7890",
		3: "+1234567890",
		4: "(123) 456-7890",
		5: "12.34.56.78.90",
	}

	for _, num := range nums {
		parsedNum, err := EnsurePhoneNumber(num)
		if err != nil {
			t.Errorf("Failed: %s\n", err.Error())
		}
		if parsedNum != "1234567890" {
			t.Errorf("Failed: Expected 1234567890, got %s\n", parsedNum)
		}
	}
}
