package auth

import "testing"

func TestPasswordHash(t *testing.T) {
	password := "MySecurePassword123@@!"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	if hash == password {
		t.Fatal("password hash must not equal plaintext password")
	}

	valid, err := CheckPassword(password, hash)
	if err != nil {
		t.Fatalf("CheckPassword() error : %v", err)
	}

	if !valid {
		t.Fatal("expected password to be valid")
	}
}


func TestWrongPassword(t *testing.T) {
	hash, err := HashPassword("CorrectPassword123@")

	if err != nil {
		t.Fatalf("HashPassword() error: %v", err)
	}

	valid, err := CheckPassword("WrongPassword@@@", hash)
	if err != nil {
		t.Fatalf("CheckPassword() error: %v", err)
	}

	if valid {
		t.Fatal("wrong password must not be valid")
	}
}
