package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)


var ErrInvalidSession = errors.New("invalid session")

type SessionRepository struct {
	db *sql.DB
}

func NewSessionRepository(db *sql.DB) *SessionRepository {
	return &SessionRepository{
		db: db,
	}
}

func (sr *SessionRepository) Create(
	ctx context.Context,
	userID string,
	accessTokenHash string,
	// refreshTokenHash string,
	accessExpiresAt time.Time,
	// refreshExpiresAt time.Time,
	deviceName string,
	deviceType string,
) (*Session, error) {
	const query = `
		INSERT INTO sessions (
			user_id,
			access_token_hash,
			access_expires_at,
			device_name,
			device_type
		)
		VALUES($1, $2, $3, $4, $5)
		RETURNING
			id,
			user_id,
			access_token_hash,
			access_expires_at,
			device_name,
			device_type,
			created_at,
			last_use_at,
			revoked_at
	`

	var session Session

	err := sr.db.QueryRowContext(
		ctx,
		query,
		userID,
		accessTokenHash,
		accessExpiresAt,
		deviceName,
		deviceType,
	).Scan(
		&session.ID,
		&session.UserID,
		&session.AccessTokenHash,
		&session.AccessExpiresAt,
		&session.DeviceName,
		&session.DeviceType,
		&session.CreatedAt,
		&session.LastUseAt,
		&session.RevokedAt,
	); 
	
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	
	return &session, nil
}

func (r *SessionRepository) CreateWithRefreshToken(
	ctx context.Context,
	userID string,
	accessTokenHash string,
	accessExpiresAt time.Time,
	refreshTokenHash string,
	refreshExpiresAt time.Time,
	deviceName string,
	deviceType string,
) (*Session, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateWithRefreshToken()-[BeginTx]: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil {
			fmt.Println("rollback: ", err)
		}
	}()

	// create session tx
	session, err := createSessionTx(
		ctx,
		tx,
		userID,
		accessTokenHash,
		accessExpiresAt,
		deviceName,
		deviceType,
	)

	if err != nil {
		return nil, err
	}

	// create refresh token tx
	_, err = createRefreshTokenTx(
		ctx,
		tx,
		session.ID,
		refreshTokenHash,
		refreshExpiresAt,
	)

	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit session transaction: %w", err)
	}

	return session, nil
}


func createSessionTx(
	ctx context.Context,
	tx *sql.Tx,
	userID string,
	accessTokenHash string,
	accessExpiresAt time.Time,
	deviceName string,
	deviceType string,
) (*Session, error) {
	const query = `
		INSERT INTO sessions (
			user_id,
			access_token_hash,
			access_expires_at,
			device_name,
			device_type
		)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING
			id,
			user_id,
			access_token_hash,
			access_expires_at,
			device_name,
			device_type,
			created_at,
			last_use_at,
			revoked_at
	`
	var session Session
	err := tx.QueryRowContext(
		ctx,
		query,
		userID,
		accessTokenHash,
		accessExpiresAt,
		deviceName,
		deviceType,
	).Scan(
		&session.ID,
		&session.UserID,
		&session.AccessTokenHash,
		&session.AccessExpiresAt,
		&session.DeviceName,
		&session.DeviceType,
		&session.CreatedAt,
		&session.LastUseAt,
		&session.RevokedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	return &session, nil
}

func createRefreshTokenTx(
	ctx context.Context,
	tx *sql.Tx,
	sessionID string,
	refreshTokenHash string,
	refreshExpiresAt time.Time,
) (*RefreshToken, error) {
	const query = `
		INSERT INTO refresh_tokens (
			session_id,
			token_hash,
			expires_at
		)
		VALUES ($1, $2, $3)
		RETURNING
			id,
			session_id,
			token_hash,
			expires_at,
			created_at,
			used_at,
			revoked_at,
			replaced_by
	`
	var token RefreshToken
	err := tx.QueryRowContext(
		ctx,
		query,
		sessionID,
		refreshTokenHash,
		refreshExpiresAt,
	).Scan(
		&token.ID,
		&token.SessionID,
		&token.TokenHash,
		&token.ExpiresAt,
		&token.CreatedAt,
		&token.UsedAt,
		&token.RevokedAt,
		&token.ReplacedBy,
	)

	if err != nil {
		return nil, fmt.Errorf("create refresh token: %w", err)
	}
	
	return &token, nil
}

func (sr *SessionRepository) FindByAccessTokenHash(
	ctx context.Context, 
	accessTokenHash string,
) (*Session, error) {
	const query = `
		SELECT 
			id,
			user_id,
			access_token_hash,
			access_expires_at,
			device_name,
			device_type,
			created_at,
			last_use_at,
			revoked_at
		FROM sessions
		WHERE access_token_hash = $1
			AND access_expires_at > NOW()
			AND revoked_at IS NULL
	`

	var session Session

	err := sr.db.QueryRowContext(
		ctx,
		query,
		accessTokenHash,
	).Scan(
		&session.ID,
		&session.UserID,
		&session.AccessTokenHash,
		&session.AccessExpiresAt,
		&session.DeviceName,
		&session.DeviceType,
		&session.CreatedAt,
		&session.LastUseAt,
		&session.RevokedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidSession
		}

		return nil, fmt.Errorf("find session by access: %w", err)
	}

	return &session, nil
}

func (sr *SessionRepository) UpdateAccessToken(
	ctx context.Context,
	sessionID string,
	tokenHash string,
	expiresAt time.Time,
) error {
	const query = `
		UPDATE sessions
		SET
			access_token_hash = $1,
			access_expires_at = $2,
			last_use_at = NOW()
		WHERE
			id = $3
			AND revoked_at IS NULL
	`

	result, err := sr.db.ExecContext(
		ctx,
		query,
		tokenHash,
		expiresAt,
		sessionID,
	)

	if err != nil {
		return fmt.Errorf("update session access token: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("get affected rows: %w", err)
	}

	if rows == 0 {
		return ErrInvalidSession
	}

	return  nil
}


func (sr *SessionRepository) Revoke(
	ctx context.Context,
	sessionID string,
) error {
	const query = `
		UPDATE sessions
		SET revoked_at = NOW()
		WHERE id = $1
			AND revoked_at IS NULL
	`

	_, err := sr.db.ExecContext(
		ctx,
		query,
		sessionID,
	)

	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}

	return nil
}

func (sr *SessionRepository) RevokeWithRefreshToken(
	ctx context.Context,
	sessionID string,
) error {
	tx, err := sr.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("RevokeWithRefreshToken() [ERROR]: begin transaction: %w", err)
	}
	defer tx.Rollback()

	const revokeSessionQuery = `
		UPDATE sessions
		SET revoked_at = NOW()
		WHERE id = $1 AND revoked_at IS NULL
	`

	_, err = tx.ExecContext(ctx, revokeSessionQuery, sessionID)
	if err != nil {
		return fmt.Errorf("RevokeWithRefreshToken() [ERROR]: revoke session: %w", err)
	}

	const revokeRefreshQuery = `
		UPDATE refresh_tokens
		SET revoked_at = NOW()
		WHERE session_id = $1 AND revoked_at IS NULL
	`
	_, err = tx.ExecContext(ctx, revokeRefreshQuery, sessionID)
	if err != nil {
		return fmt.Errorf("RevokeWithRefreshToken() [ERROR]: revoke refresh tokens: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("RevokeWithRefreshToken() [ERROR]: %w", err)
	}

	return nil
}
