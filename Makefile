BINARY      := bin/server
TAILWIND    := ./bin/tailwindcss
TAILWIND_V  := v3.4.17
CSS_IN      := web/input.css
CSS_OUT     := internal/delivery/http/static/app.css

# Detect the platform for the standalone Tailwind download.
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_S),Darwin)
  ifeq ($(UNAME_M),arm64)
    TW_ASSET := tailwindcss-macos-arm64
  else
    TW_ASSET := tailwindcss-macos-x64
  endif
else
  ifeq ($(UNAME_M),aarch64)
    TW_ASSET := tailwindcss-linux-arm64
  else
    TW_ASSET := tailwindcss-linux-x64
  endif
endif

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: env
env: ## Create .env with generated secrets, unless one already exists
	@if [ -f .env ]; then \
		echo ".env already exists, leaving it alone"; \
	else \
		cp .env.example .env; \
		sed -i.bak "s|^APP_ENCRYPTION_KEY=.*|APP_ENCRYPTION_KEY=$$(openssl rand -base64 32)|" .env; \
		sed -i.bak "s|^SESSION_SECRET=.*|SESSION_SECRET=$$(openssl rand -base64 32)|" .env; \
		ADMIN_PW=$$(openssl rand -base64 18); \
		sed -i.bak "s|^ADMIN_INITIAL_PASSWORD=.*|ADMIN_INITIAL_PASSWORD=$$ADMIN_PW|" .env; \
		rm -f .env.bak; \
		echo "Created .env with a generated APP_ENCRYPTION_KEY, SESSION_SECRET, and admin password"; \
		echo "First login: admin@example.com / $$ADMIN_PW (you'll be forced to change it)"; \
	fi

.PHONY: db
db: ## Start Postgres in Docker
	docker compose up -d postgres

.PHONY: db-down
db-down: ## Stop Postgres
	docker compose down

.PHONY: run
run: ## Run the server (migrations apply automatically at boot)
	go run ./cmd/server

.PHONY: build
build: css ## Build the binary with embedded assets
	go build -trimpath -o $(BINARY) ./cmd/server

.PHONY: css
css: $(TAILWIND) ## Rebuild the Tailwind stylesheet
	$(TAILWIND) -c tailwind.config.js -i $(CSS_IN) -o $(CSS_OUT) --minify

.PHONY: css-watch
css-watch: $(TAILWIND) ## Rebuild the stylesheet on every template change
	$(TAILWIND) -c tailwind.config.js -i $(CSS_IN) -o $(CSS_OUT) --watch

$(TAILWIND):
	@mkdir -p bin
	curl -fsSL -o $(TAILWIND) \
		https://github.com/tailwindlabs/tailwindcss/releases/download/$(TAILWIND_V)/$(TW_ASSET)
	chmod +x $(TAILWIND)

.PHONY: test
test: ## Run the test suite
	go test ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: tidy
tidy: ## Tidy go.mod
	go mod tidy

.PHONY: docker
docker: env ## Build and run everything in Docker (generates .env on first run)
	docker compose up --build
