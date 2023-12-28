test:
	go test -v -race -cover -coverprofile=coverage.out -covermode=atomic ./...

.PHONY: test
