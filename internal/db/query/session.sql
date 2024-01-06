-- name: CreateSession :one
INSERT INTO sessions (
    id,
    wallet_address,
    refresh_token,
    user_agent,
    client_ip,
    expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6
) RETURNING *;

-- name: GetSession :one
SELECT * FROM sessions
WHERE id = $1 LIMIT 1;

-- name: RevokeAccountSessions :execresult
UPDATE sessions
SET is_revoked = true
WHERE wallet_address = $1 AND is_revoked = false;
