-- +goose Up
CREATE TABLE IF NOT EXISTS chirps (
  id UUID PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  body TEXT NOT NULL,
  user_id UUID NOT NULL,
  CONSTRAINT fk_chirps_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- +goose Down
DROP TABLE IF EXISTS chirps;
