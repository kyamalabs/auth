-- name: CreateAccount :one
INSERT INTO accounts (
    owner
) VALUES (
    $1
) RETURNING *;
