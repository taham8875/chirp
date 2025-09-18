-- name: CreateUser :one
INSERT INTO users (
    id,
    email,
    hashed_password,
    created_at,
    updated_at
) VALUES ( 
    gen_random_uuid(),
    $1,
    $2,
    NOW(),
    NOW()
)

RETURNING *;

-- name: UpdateUser :one
UPDATE users
SET 
    email = $2,
    hashed_password = $3,
    updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: DeleteAllUsers :exec
DELETE FROM users;

-- name: GetUserByEmail :one
SELECT id, email, hashed_password, created_at, updated_at FROM users WHERE email = $1;
