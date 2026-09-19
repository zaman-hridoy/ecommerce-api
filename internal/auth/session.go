package auth

import "time"

type Session struct {
	ID					string
	UserID				string
	AccessTokenHash		string
	// RefreshTokenHash	string

	AccessExpiresAt		time.Time
	// RefreshExpiresAt	time.Time

	DeviceName			string
	DeviceType			string

	CreatedAt			time.Time
	LastUseAt			time.Time
	RevokedAt			*time.Time
}

type RefreshToken struct {
	ID			string
	SessionID	string
	TokenHash	string
	ExpiresAt   time.Time
	CreatedAt	time.Time
	UsedAt		*time.Time
	RevokedAt	*time.Time
	ReplacedBy	*string
}