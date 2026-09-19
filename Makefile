.PHONY: build run migrate-force

build:
	go build -o ./bin/api ./cmd/api

run: build
	./bin/api

migrate-up:
	go run ./cmd/migrate -direction=up

migrate-down:
	go run ./cmd/migrate -direction=down

migrate-force:
	@test -n "$(version)" || (echo "version is required. Usage: make migrate-force version=3"; exit 1)
	go run ./cmd/migrate -force=$(version)

build-migrate:
	go build -o bin/migrate ./cmd/migrate