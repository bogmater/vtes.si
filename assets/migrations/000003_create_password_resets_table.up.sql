CREATE TABLE password_resets (
    hashed_token TEXT NOT NULL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expiry TIMESTAMP NOT NULL
);

CREATE INDEX idx_password_resets_user_id ON password_resets(user_id);
