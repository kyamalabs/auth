-- SQL dump generated using DBML (dbml-lang.org)
-- Database: PostgreSQL
-- Generated at: 2023-12-29T00:29:06.724Z

CREATE TABLE "accounts" (
  "id" UUID PRIMARY KEY DEFAULT (gen_random_uuid()),
  "owner" varchar UNIQUE NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "sessions" (
  "id" UUID PRIMARY KEY,
  "wallet_address" varchar UNIQUE NOT NULL,
  "refresh_token" varchar UNIQUE NOT NULL,
  "user_agent" varchar NOT NULL,
  "client_ip" varchar NOT NULL,
  "is_revoked" boolean NOT NULL DEFAULT false,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE INDEX ON "accounts" ("owner");

CREATE INDEX ON "sessions" ("wallet_address");

CREATE INDEX ON "sessions" ("refresh_token");

ALTER TABLE "sessions" ADD FOREIGN KEY ("wallet_address") REFERENCES "accounts" ("owner");
