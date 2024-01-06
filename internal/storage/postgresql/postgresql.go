package postgresql

import (
	"authorizationMicroservice/internal/domain/models"
	"context"
	"database/sql"
	"fmt"
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
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &user, err
}

func (s *Storage) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	panic("implement this")
}

func (s *Storage) App(ctx context.Context, appID int) (*models.App, error) {
	panic("implement this")
}
