package auth

import (
	"context"
	"fmt"
	"testing"

	"github.com/zaman-hridoy/ecommerce-api/internal/user"
)


type fakeUserRepository struct {
	createFunc func(
		ctx context.Context,
		name, email, passwordHash string,
	) (*user.User, error)
	
} 

func (f *fakeUserRepository) Create(
	ctx context.Context,
	name, email, passwordHash string,
) (*user.User, error) {
	return f.createFunc(ctx, name, email, passwordHash)
}


func TestRegisterSuccess(t *testing.T) {
	repo := &fakeUserRepository{
		createFunc: func(ctx context.Context, name, email, passwordHash string) (*user.User, error) {
			if name != "Zaman Hridoy" {
				t.Fatalf("expected normalized name, got %q", name)
			}

			if name != "zaman@example.com" {
				t.Fatalf("expected normalized email, got %q", email)
			}

			if passwordHash != "VeryStrongPassword123!" {
				t.Fatal("password must be hashed")
			}

			valid, err := CheckPassword("VeryStrongPassword123!", passwordHash)

			if err != nil {
				t.Fatalf("CheckPassword() error: %v", err)
			}

			if !valid {
				t.Fatal("stored hash does not match password")
			}

			return &user.User{
				ID: "user-123",
				Name: name,
				Email: email,
			}, nil
		},
	}


	// service := NewService(repo)
	fmt.Println(repo)
}