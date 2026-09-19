package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)


var (
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	ErrRefreshTokenUsed = errors.New("refresh token already used")
	ErrRefreshTokenExpired = errors.New("refresh token expired")
	ErrRefreshTokenRevoked = errors.New("refresh token revoked")
)

type RefreshRepository struct {
	db *sql.DB
}

func NewRefreshRepository(db *sql.DB) *RefreshRepository {
	return &RefreshRepository{
		db: db,
	}
}

func (r *RefreshRepository) Create(
	ctx context.Context,
	sessionID string,
	tokenHash string,
	expiresAt time.Time,
) (*RefreshToken, error) {
	query := `
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
	err := r.db.QueryRowContext(
		ctx,
		query,
		sessionID,
		tokenHash,
		expiresAt,
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


func (r *RefreshRepository) FindByHash(
	ctx context.Context, 
	tokenHash string,
) (*RefreshToken, error) {
	query := `
		SELECT
			id,
			session_id,
			token_hash,
			expires_at,
			created_at,
			used_at,
			revoked_at,
			replaced_by
		FROM refresh_tokens
		WHERE token_hash = $1
	`

	var token RefreshToken
	err := r.db.QueryRowContext(
		ctx,
		query,
		tokenHash,
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
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRefreshTokenNotFound
		}

		return nil, fmt.Errorf("find refresh token: %w", err)
	}

	return &token, nil
}


func (r *RefreshRepository) Rotate(
	ctx context.Context,
	oldTokenID string,
	sessionID string,
	newRefreshHash string,
	newRefreshExpiresAt time.Time,
	newAccessHash string,
	newAccessExpiresAt time.Time,
)(*RefreshToken, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin refresh transaction: %w", err)
	}

	defer tx.Rollback()

	// create new refresh token
	const createQuery = `
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

	var newToken RefreshToken
	err = tx.QueryRowContext(
		ctx,
		createQuery,
		sessionID,
		newRefreshHash,
		newRefreshExpiresAt,
	).Scan(
		&newToken.ID, 
		&newToken.SessionID, 
		&newToken.TokenHash, 
		&newToken.ExpiresAt, 
		&newToken.CreatedAt, 
		&newToken.UsedAt, 
		&newToken.RevokedAt, 
		&newToken.ReplacedBy, 
	)

	if err != nil {
		return nil, fmt.Errorf("create replacement refresh token: %w", err)
	}


	// update old refresh token
	const useOldQuery = `
		UPDATE refresh_tokens
		SET
			used_at = NOW(),
			replaced_by = $1
		WHERE id = $2
			AND used_at IS NULL
	`

	result, err := tx.ExecContext(
		ctx,
		useOldQuery,
		newToken.ID,
		oldTokenID,
	)

	if err != nil {
		return nil, fmt.Errorf("consume refresh token: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("replaced rows affected: %w", err)
	}

	if rows != 1 {
		return nil, ErrRefreshTokenUsed
	}

// old: 01eee008-97d1-42f5-be99-4cb0aacb24cf

	// update access token
	const updateSessionQuery = `
		UPDATE sessions
		SET
			access_token_hash = $1,
			access_expires_at = $2,
			last_use_at = NOW()
		WHERE id = $3
			AND revoked_at IS NULL
	`

	result, err = tx.ExecContext(
		ctx,
		updateSessionQuery,
		newAccessHash,
		newAccessExpiresAt,
		sessionID,
	)

	rows, err = result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("session rows affected: %w", err)
	}

	if rows != 1 {
		return nil, ErrInvalidSession
	}


	// commit the changes
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit refresh transaction: %w", err)
	}

	return &newToken, nil
}


func (r *RefreshRepository) RevokeBySessionID(
	ctx context.Context,
	sessionID string,
) error {
	const query = `
		UPDATE refresh_tokens
		SET revoked_at = NOW()
		WHERE session_id = $1
			AND revoked_at IS NULL
	`

	_, err := r.db.ExecContext(ctx, query, sessionID)
	if err != nil {
		return fmt.Errorf("RevokeBySessionID() [revoke refresh token]: %w", err)
	}

	return nil
}