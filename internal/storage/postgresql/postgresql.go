package postgresql

import (
	"authorizationMicroservice/internal/domain/models"
	"authorizationMicroservice/internal/storage"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type Storage struct {
	db *sql.DB
}

func New(databaseURL string) (*Storage, error) {
	const op = "storage.postgresql.New"

	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &Storage{db: db}, nil
}

func (s *Storage) SaveUser(ctx context.Context, email string, passHash []byte) (uid int64, err error) {
	const op = "storage.postgresql.SaveUser"

	stmt, err := s.db.Prepare(`INSERT INTO users(email, pass_hash) VALUES($1, $2) RETURNING id`)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	result := stmt.QueryRowContext(ctx, email, passHash)

	var id int64

	err = result.Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" {
				// Handle the duplicate key error
				return 0, fmt.Errorf("%s: %w", op, storage.ErrUserExists)
			}
		}
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

func (s *Storage) User(ctx context.Context, email string) (*models.User, error) {
	const op = "storage.postgresql.User"

	stmt, err := s.db.Prepare(`SELECT id, email, pass_hash FROM users WHERE email = $1`)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	result := stmt.QueryRowContext(ctx, email)

	var user models.User

	err = result.Scan(&user.ID, &user.Email, &user.PassHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &user, nil
}

func (s *Storage) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "storage.postgresql.IsAdmin"

	stmt, err := s.db.Prepare(`SELECT is_admin FROM users WHERE id = $1`)
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	result := stmt.QueryRowContext(ctx, userID)

	var isAdmin bool

	err = result.Scan(&isAdmin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return isAdmin, nil
}

func (s *Storage) App(ctx context.Context, appID int) (*models.App, error) {
	const op = "storage.postgresql.App"

	stmt, err := s.db.Prepare(`SELECT id, name, secret FROM apps WHERE id = $1`)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	result := stmt.QueryRowContext(ctx, appID)

	var app models.App

	err = result.Scan(&app.ID, &app.Name, &app.Secret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &app, nil
}
