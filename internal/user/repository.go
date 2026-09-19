package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
)


var (
	ErrNotFound = errors.New("user not found")
	ErrEmailExists = errors.New("user email already exists")
)

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{
		db: db,
	}
}


func (r *Repository) Create(
	ctx context.Context,
	name string,
	email string,
	passwordHash string,
) (*User, error) {

	query := `
		INSERT INTO users (
			name,
			email,
			password_hash
		)
		VALUES ($1, $2, $3)
		RETURNING id, name, email, password_hash, created_at, updated_at
	`

	var u User

	err := r.db.QueryRowContext(
		ctx,
		query,
		name,
		email,
		passwordHash,
	).Scan(&u.ID, &u.Name, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt)
	
	if err != nil {
		var pgErr *pgconn.PgError

		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrEmailExists
		}
		return nil, fmt.Errorf("create user: %w", err)
	}

	return &u, nil
}

func (r *Repository) FindByEmail(
	ctx context.Context,
	email string,
) (*User, error) {
	query := `
		SELECT
			id,
			name,
			email,
			password_hash,
			created_at,
			updated_at
		FROM users
		WHERE email = $1
	`

	var u User
	err := r.db.QueryRowContext(ctx, query, email).Scan(&u.ID, &u.Name, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("find user by email: %w", err)
	}

	return &u, nil
}


func (r *Repository) FindByID(ctx context.Context, id string) (*User, error) {
	query := `
		SELECT
			id,
			name,
			email,
			created_at,
			updated_at
		FROM users
		WHERE id = $1
	`
	var u User
	err := r.db.QueryRowContext(ctx, query, id).Scan(&u.ID, &u.Name, &u.Email, &u.CreatedAt, &u.UpdatedAt)

	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}

		return nil, fmt.Errorf("find user by id: %w", err)
	}

	return &u, nil
}