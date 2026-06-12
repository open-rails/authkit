# Pinned sqlc version; `go run` keeps the tool out of the library's go.mod.
SQLC_VERSION ?= v1.31.1
SQLC := go run github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION)

# sqlc vet's db-prepare rule PREPAREs every query against a real database.
# Defaults to the devserver Postgres (docker compose -f
# docker-compose.devserver.yaml up -d postgres) with migrations applied.
SQLC_DATABASE_URL ?= postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable
export SQLC_DATABASE_URL

.PHONY: sqlc
sqlc: ## Regenerate type-safe query code and lint queries (generate + vet, always as a pair)
	$(SQLC) generate
	$(SQLC) vet

.PHONY: sqlc-check
sqlc-check: sqlc ## CI guard: fail if committed generated code drifts from queries
	git diff --exit-code -- internal/db

.PHONY: test
test:
	AUTHKIT_TEST_DATABASE_URL="$(SQLC_DATABASE_URL)" go test ./...
