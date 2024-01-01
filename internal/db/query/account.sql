-- name: CreateAccount :one
INSERT INTO accounts (
    owner
) VALUES (
    $1
) RETURNING *;

-- name: GetAccountByOwner :one
SELECT * FROM accounts
WHERE owner = $1 LIMIT 1;
