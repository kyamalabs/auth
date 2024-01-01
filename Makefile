DB_USER = root
DB_PORT = 5432
DB_PASS = password
DATABASE_NAME = auth
POSTGRES_VERSION = 16
DATABASE_URL = "postgresql://$(DB_USER):$(DB_PASS)@localhost:$(DB_PORT)/$(DATABASE_NAME)?sslmode=disable"

SHORT = true

test:
	go test -v -race -cover -coverprofile=coverage.out -covermode=atomic -short=$(SHORT) ./...

db_docs:
	dbdocs build docs/db.dbml

db_schema:
	dbml2sql --postgres -o docs/db_schema.sql docs/db.dbml

postgres:
	docker run --name postgres$(POSTGRES_VERSION) -p $(DB_PORT):$(DB_PORT) -e POSTGRES_USER=$(DB_USER) -e POSTGRES_PASSWORD=$(DB_PASS) -d postgres:$(POSTGRES_VERSION)-alpine

create_db:
	docker exec -it postgres$(POSTGRES_VERSION) createdb --username=$(DB_USER) --owner=$(DB_USER) $(DATABASE_NAME)

drop_db:
	docker exec -it postgres$(POSTGRES_VERSION) dropdb $(DATABASE_NAME)

migrate_create:
	migrate create -ext sql -dir internal/db/migration -seq $(name)

migrate_up:
ifdef N
	migrate -path internal/db/migration -database $(DATABASE_URL) -verbose up $(N)
else
	migrate -path internal/db/migration -database $(DATABASE_URL) -verbose up
endif

migrate_down:
ifdef N
	migrate -path internal/db/migration -database $(DATABASE_URL) -verbose down $(N)
else
	migrate -path internal/db/migration -database $(DATABASE_URL) -verbose down
endif

mock:
	mockgen -package=mockdb -destination=internal/db/mock/store.go github.com/kyamagames/auth/internal/db/sqlc Store

sqlc:
	sqlc generate
	@$(MAKE) mock

proto:
	rm -f api/pb/*.go
	protoc --proto_path=api/proto --go_out=api/pb --go_opt=paths=source_relative \
	--go-grpc_out=api/pb --go-grpc_opt=paths=source_relative \
	--grpc-gateway_out=api/pb --grpc-gateway_opt=paths=source_relative \
	api/proto/*.proto

server:
	go run ./cmd/auth

evans:
	evans --host localhost --port 50051 -r repl

.PHONY: test db_docs db_schema postgres create_db drop_db migrate_create migrate_up migrate_down sqlc mock proto server evans
