package database

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type PasswordReset struct {
	HashedToken string    `db:"hashed_token"`
	UserID      int       `db:"user_id"`
	Expiry      time.Time `db:"expiry"`
}

func (db *DB) InsertPasswordReset(hashedToken string, userID int, ttl time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	query := `
		INSERT INTO password_resets (hashed_token, user_id, expiry)
		VALUES ($1, $2, $3)`

	_, err := db.ExecContext(ctx, query, hashedToken, userID, time.Now().Add(ttl))
	return err
}

func (db *DB) GetPasswordReset(hashedToken string) (*PasswordReset, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	var passwordReset PasswordReset

	query := `
		SELECT * FROM password_resets 
		WHERE hashed_token = $1 AND expiry > $2`

	err := db.GetContext(ctx, &passwordReset, query, hashedToken, time.Now())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}

	return &passwordReset, true, err
}

func (db *DB) DeletePasswordResets(userID int) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	query := `DELETE FROM password_resets WHERE user_id = $1`

	_, err := db.ExecContext(ctx, query, userID)
	return err
}
