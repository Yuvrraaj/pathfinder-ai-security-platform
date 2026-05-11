# PathFinder Makefile
# Convenience targets for Docker operations

.PHONY: build run demo scan labs-up labs-down shell clean help

# Default target
.DEFAULT_GOAL := help

# Detect docker compose command (v2 plugin vs standalone)
DOCKER_COMPOSE := $(shell docker compose version >/dev/null 2>&1 && echo "docker compose" || echo "docker-compose")

# =============================================================================
# Build Targets
# =============================================================================

build: ## Build the PathFinder Docker image
	$(DOCKER_COMPOSE) build

build-no-cache: ## Build without cache
	$(DOCKER_COMPOSE) build --no-cache

# =============================================================================
# Run Targets
# =============================================================================

run: ## Run pathfinder with arguments: make run CMD="status"
	$(DOCKER_COMPOSE) run --rm pathfinder $(CMD)

demo: ## Run demo assessment and output HTML report
	$(DOCKER_COMPOSE) run --rm pathfinder demo -o /home/pathfinder/.pathfinder/demo-report.html
	@echo "Report saved to output/demo-report.html"

scan: ## Run scan against target: make scan TARGET="http://juice-shop:3000"
	$(DOCKER_COMPOSE) run --rm pathfinder run $(TARGET)

status: ## Check pathfinder status and scanner availability
	$(DOCKER_COMPOSE) run --rm pathfinder status

shell: ## Open interactive shell in PathFinder container
	$(DOCKER_COMPOSE) run --rm --entrypoint bash pathfinder

# =============================================================================
# Vulnerable Lab Targets
# =============================================================================

labs-up: ## Start all vulnerable lab containers
	$(DOCKER_COMPOSE) --profile labs up -d
	@echo ""
	@echo "Lab containers starting..."
	@echo "  - Juice Shop:  http://localhost:3000"
	@echo "  - DVWA:        http://localhost:8081"
	@echo "  - WebGoat:     http://localhost:8080"
	@echo ""
	@echo "Wait for healthchecks before scanning."
	@echo "Check status with: docker compose --profile labs ps"

labs-down: ## Stop all vulnerable lab containers
	$(DOCKER_COMPOSE) --profile labs down

labs-status: ## Check status of lab containers
	$(DOCKER_COMPOSE) --profile labs ps

# =============================================================================
# Scan Lab Targets
# =============================================================================

scan-juice-shop: labs-up ## Scan Juice Shop (starts labs if needed)
	@echo "Waiting for Juice Shop to be healthy..."
	@sleep 10
	$(DOCKER_COMPOSE) run --rm pathfinder run http://juice-shop:3000

scan-dvwa: labs-up ## Scan DVWA (starts labs if needed)
	@echo "Waiting for DVWA to be healthy..."
	@sleep 15
	$(DOCKER_COMPOSE) run --rm pathfinder run http://dvwa

scan-webgoat: labs-up ## Scan WebGoat (starts labs if needed)
	@echo "Waiting for WebGoat to be healthy (this takes ~3 minutes)..."
	@sleep 180
	$(DOCKER_COMPOSE) run --rm pathfinder run http://webgoat:8080

# =============================================================================
# Cleanup Targets
# =============================================================================

clean: ## Remove output and reports directories
	rm -rf output/ reports/
	@echo "Cleaned output/ and reports/"

clean-all: clean ## Remove all artifacts including Docker volumes
	$(DOCKER_COMPOSE) down -v
	docker volume rm pathfinder-nuclei-templates 2>/dev/null || true
	@echo "Cleaned all Docker artifacts"

# =============================================================================
# Help
# =============================================================================

help: ## Show this help message
	@echo "PathFinder Docker Makefile"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
