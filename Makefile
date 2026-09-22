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

.PHONY: docker-image
docker-image: ## Build the app image for a Swarm deploy (docker-stack.yml)
	docker build -t ssl-tower:1.1 .

.PHONY: docker-secrets
docker-secrets: ## Create every Docker secret docker-stack.yml needs, sourced from .env where a value exists (unless the secret already exists)
	@command -v docker >/dev/null || { echo "docker is required"; exit 1; }
	@env_val() { \
		[ -f .env ] || return 0; \
		line=$$(grep -E "^$$1=" .env | tail -1); \
		val=$${line#*=}; \
		case "$$val" in \
			\"*\") val=$${val#\"}; val=$${val%\"} ;; \
			\'*\') val=$${val#\'}; val=$${val%\'} ;; \
		esac; \
		printf '%s' "$$val"; \
	}; \
	create_if_missing() { \
		name=$$1; value=$$2; \
		if docker secret inspect $$name >/dev/null 2>&1; then \
			echo "$$name already exists, leaving it alone"; \
		else \
			printf '%s' "$$value" | docker secret create $$name - >/dev/null; \
			echo "created $$name"; \
		fi; \
	}; \
	DB_URL_FROM_ENV=$$(env_val DATABASE_URL); \
	DB_PASSWORD=$$(printf '%s' "$$DB_URL_FROM_ENV" | sed -n 's#^postgres://[^:]*:\([^@]*\)@.*#\1#p'); \
	if [ -z "$$DB_PASSWORD" ]; then \
		DB_PASSWORD=$$(openssl rand -base64 24); \
		echo "no DATABASE_URL password found in .env — generated a fresh one for the Swarm secrets"; \
	else \
		echo "reusing the DB password already in .env's DATABASE_URL"; \
	fi; \
	create_if_missing ssl_tower_db_password "$$DB_PASSWORD"; \
	create_if_missing ssl_tower_database_url "postgres://ssl_tower:$$DB_PASSWORD@postgres:5432/ssl_generator?sslmode=disable"; \
	ENC_KEY=$$(env_val APP_ENCRYPTION_KEY); [ -n "$$ENC_KEY" ] || ENC_KEY=$$(openssl rand -base64 32); \
	create_if_missing ssl_tower_encryption_key "$$ENC_KEY"; \
	SESSION_SECRET=$$(env_val SESSION_SECRET); [ -n "$$SESSION_SECRET" ] || SESSION_SECRET=$$(openssl rand -base64 32); \
	create_if_missing ssl_tower_session_secret "$$SESSION_SECRET"; \
	ADMIN_PW=$$(env_val ADMIN_INITIAL_PASSWORD); \
	if [ -z "$$ADMIN_PW" ]; then \
		ADMIN_PW=$$(openssl rand -base64 18); \
		echo "First login (only takes effect on a clean database): admin@example.com / $$ADMIN_PW"; \
	else \
		echo "using the ADMIN_INITIAL_PASSWORD already in .env"; \
	fi; \
	create_if_missing ssl_tower_admin_password "$$ADMIN_PW"; \
	SMTP_PW=$$(env_val SMTP_PASSWORD); \
	if [ -n "$$SMTP_PW" ]; then \
		create_if_missing ssl_tower_smtp_password "$$SMTP_PW"; \
	else \
		echo "SMTP_PASSWORD is empty in .env — skipping ssl_tower_smtp_password (leave it commented out in docker-stack.yml too, or email alerts stay off)"; \
	fi; \
	TEAMS_URL=$$(env_val TEAMS_WEBHOOK_URL); \
	if [ -n "$$TEAMS_URL" ]; then \
		create_if_missing ssl_tower_teams_webhook "$$TEAMS_URL"; \
	else \
		echo "TEAMS_WEBHOOK_URL is empty in .env — skipping ssl_tower_teams_webhook (leave it commented out in docker-stack.yml too, or Teams alerts stay off)"; \
	fi; \
	LDAP_PW=$$(env_val LDAP_BIND_PASSWORD); \
	if [ -n "$$LDAP_PW" ]; then \
		create_if_missing ssl_tower_ldap_bind_password "$$LDAP_PW"; \
	else \
		echo "LDAP_BIND_PASSWORD is empty in .env — skipping ssl_tower_ldap_bind_password (leave it commented out in docker-stack.yml too; LDAP can still be configured later from /settings)"; \
	fi; \
	ADCS_PW=$$(env_val ADCS_PASSWORD); \
	if [ -n "$$ADCS_PW" ]; then \
		create_if_missing ssl_tower_adcs_password "$$ADCS_PW"; \
	else \
		echo "ADCS_PASSWORD is empty in .env — skipping ssl_tower_adcs_password (leave it commented out in docker-stack.yml too, or the ADCS integration stays off)"; \
	fi; \
	GRAPH_SECRET=$$(env_val GRAPH_CLIENT_SECRET); \
	if [ -n "$$GRAPH_SECRET" ]; then \
		create_if_missing ssl_tower_graph_client_secret "$$GRAPH_SECRET"; \
	else \
		echo "GRAPH_CLIENT_SECRET is empty in .env — skipping ssl_tower_graph_client_secret (leave it commented out in docker-stack.yml too; Graph API email can still be configured later from /settings)"; \
	fi
	@echo "Re-run 'docker secret inspect <name>' any time to check what exists — a secret already created is left untouched, since Docker secrets are immutable. To pick up a changed .env value, create a new secret under a new name and update docker-stack.yml's reference to it (see that file's header comment)."

.PHONY: docker-stack-deploy
docker-stack-deploy: docker-image docker-secrets ## Build, create secrets, and deploy the Swarm stack
	docker stack deploy -c docker-stack.yml ssltower
