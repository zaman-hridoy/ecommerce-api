package auth

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/zaman-hridoy/ecommerce-api/internal/user"
)


var (
	ErrNameRequired		= errors.New("name is required")
	ErrEmailRequired	= errors.New("email is required")
	ErrInvalidEmail		= errors.New("invalid email")
	ErrPasswordRequired = errors.New("password is required")
	ErrPasswordTooShort = errors.New("password must be at least 8 characters")
	ErrEmailAlreadyExists = errors.New("email already exists")

	ErrInvalidCredentials = errors.New("invalid email or password")
)

func isValidEmail(email string) bool {
	parsed, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}

	if parsed.Address != email {
		return false
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	domain := parts[1]
	if !strings.Contains(domain, ".") {
		return false
	}

	return true
}

type UserRepository interface {
	Create(ctx context.Context, name, email, password string) (*user.User, error)
	FindByEmail(ctx context.Context, email string) (*user.User, error)
}

type Service struct {
	// users *user.Repository
	users UserRepository
	sessions *SessionRepository
	refreshTokens *RefreshRepository
}

func NewService(users *user.Repository, sessions *SessionRepository, refreshTokens *RefreshRepository) *Service {
	return &Service{
		users: users,
		sessions: sessions,
		refreshTokens: refreshTokens,
	}
}


type RegisterInput struct {
	Name string
	Email string
	Password string
}

func (s *Service) Register(ctx context.Context, input RegisterInput) (*user.User, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	input.Password = strings.TrimSpace(input.Password)

	if input.Name == "" {
		return nil, ErrNameRequired
	}

	if input.Email == "" {
		return nil, ErrEmailRequired
	}

	if !isValidEmail(input.Email) {
		return nil, ErrInvalidEmail
	}

	if input.Password == "" {
		return nil, ErrPasswordRequired
	}

	if len(input.Password) < 8 {
		return nil, ErrPasswordTooShort
	}

	// existingUser, err := s.users.FindByEmail(ctx, input.Email)
	// if err == nil && existingUser != nil {
	// 	return nil, ErrEmailAlreadyExists
	// }

	// if err != nil && !errors.Is(err, user.ErrNotFound) { // database/system error
	// 	return nil, err
	// }

	passwordHash, err := HashPassword(input.Password)
	if err != nil {
		return nil, err
	}

	createdUser, err := s.users.Create(ctx, input.Name, input.Email, passwordHash)

	if err != nil {
		if errors.Is(err, user.ErrEmailExists) {
			return nil, ErrEmailAlreadyExists
		}
		return nil, err
	}

	return createdUser, nil
}


type LoginInput struct {
	Email string
	Password string
	DeviceName string
	DeviceType string
}

type LoginResult struct {
	User *user.User
	SessionID string
	AccessToken string
	RefreshToken string

	AccessExpiresAt time.Time
	RefreshExpiresAt time.Time
}

func (s *Service) Login(
	ctx context.Context,
	input LoginInput,
) (*LoginResult, error) {
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	input.Password = strings.TrimSpace(input.Password)

	if input.Email == "" || input.Password == "" {
		return nil, ErrInvalidCredentials
	}

	u, err := s.users.FindByEmail(ctx, input.Email)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			return nil, ErrInvalidCredentials
		}

		return nil, err
	}

	valid, err := CheckPassword(input.Password, u.PasswordHash)
	if err != nil {
		return nil, err
	}

	if !valid {
		return nil, ErrInvalidCredentials
	}

	accessToken, err := GenerateToken() // not hashed token
	if err != nil {
		return nil, err
	}

	refreshToken, err := GenerateToken()
	if err != nil {
		return nil, err
	}

	accessTokenHash := HashToken(accessToken)
	refreshTokenHash := HashToken(refreshToken)

	now := time.Now().UTC()
	accessExpiresAt := now.Add(1 * time.Minute)
	refreshExpiresAt := now.Add(time.Minute * 5)

	// session, err := s.sessions.Create(
	// 	ctx,
	// 	u.ID,
	// 	accessTokenHash,
	// 	accessExpiresAt,
	// 	input.DeviceName,
	// 	input.DeviceType,
	// )

	// if err != nil {
	// 	return nil, err
	// }

	// _, err = s.refreshTokens.Create(
	// 	ctx,
	// 	session.ID,
	// 	refreshTokenHash,
	// 	refreshExpiresAt,
	// )

	// if err != nil {
	// 	return nil, err
	// }


	session, err := s.sessions.CreateWithRefreshToken(
		ctx,
		u.ID,
		accessTokenHash,
		accessExpiresAt,
		refreshTokenHash,
		refreshExpiresAt,
		input.DeviceName,
		input.DeviceType,
	)

	if err != nil {
		return nil, err
	}

	return &LoginResult{
		User: u,
		SessionID: session.ID,
		AccessToken: accessToken,
		RefreshToken: refreshToken,
		AccessExpiresAt: accessExpiresAt,
		RefreshExpiresAt: refreshExpiresAt,
	}, nil
}


type RefreshInput struct {
	RefreshToken string
}


type RefreshResult struct {
	AccessToken string
	RefreshToken string

	AccessExpiresAt time.Time
	RefreshExpiresAt time.Time
}


func (s *Service) Refresh(
	ctx context.Context,
	input RefreshInput,
) (*RefreshResult, error) {
	if input.RefreshToken == "" {
		return nil, ErrInvalidSession
	}

	refreshHash := HashToken(input.RefreshToken)


	current, err := s.refreshTokens.FindByHash(ctx, refreshHash)

	if err != nil {
		return nil, ErrInvalidSession
	}

	if current.RevokedAt != nil {
		return nil, ErrInvalidSession
	}

	now := time.Now().UTC()

	if !current.ExpiresAt.After(now) {
		return nil, ErrInvalidSession
	}

	if current.UsedAt != nil {
		_ = s.sessions.Revoke(ctx, current.SessionID)

		return nil, ErrInvalidSession
	}

	newAccessToken, err := GenerateToken()
	if err != nil {
		return nil, err
	}

	newRefreshToken, err := GenerateToken()
	if err != nil {
		return nil, err
	}

	newAccessHash := HashToken(newAccessToken)
	newRefreshHash := HashToken(newRefreshToken)

	accessExpiresAt := now.Add(1 * time.Minute)
	refreshExpiresAt := now.Add(5 * time.Minute)


	_, err = s.refreshTokens.Rotate(
		ctx,
		current.ID,
		current.SessionID,
		newRefreshHash,
		refreshExpiresAt,
		newAccessHash,
		accessExpiresAt,
	)

	fmt.Println("err", err)

	if err != nil {
		if errors.Is(err, ErrRefreshTokenUsed) {
			_ = s.sessions.Revoke(ctx, current.SessionID)

			return nil, ErrInvalidSession
		}

		return nil, err
	}

	return &RefreshResult{
		AccessToken: newAccessToken,
		RefreshToken: newRefreshToken,
		AccessExpiresAt: accessExpiresAt,
		RefreshExpiresAt: refreshExpiresAt,
	}, nil
}


func (s *Service) Logout(
	ctx context.Context,
	sessionID string,
) error {
	if sessionID == "" {
		return ErrInvalidSession
	}
	err := s.sessions.RevokeWithRefreshToken(ctx, sessionID)
	if err != nil {
		return err
	}
	return nil
}