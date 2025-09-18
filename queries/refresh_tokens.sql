-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (user_id, token, expires_at, created_at, updated_at)
VALUES ($1, $2, $3, NOW(), NOW())
RETURNING *;

-- name: GetUserFromRefreshToken :one
SELECT u.id, u.email, u.created_at, u.updated_at
FROM users u
JOIN refresh_tokens rt ON u.id = rt.user_id
WHERE rt.token = $1 AND (rt.revoked_at IS NULL AND rt.expires_at > NOW());

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW(), updated_at = NOW()
WHERE token = $1;
