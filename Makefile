# Non-destructive quality gates. Never pull or start legacy images here.
SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
PYTHON ?= python3
COMPOSE ?= docker compose

.PHONY: lint test compose-check resolved-check check

lint:
	$(PYTHON) -m compileall -q scripts tests

test:
	$(PYTHON) -m unittest discover -s tests -v

compose-check:
	$(COMPOSE) -f docker-compose.yml config --quiet

# No secrets are printed. This command validates the interpolated JSON model.
resolved-check:
	$(COMPOSE) --env-file .env.example -f docker-compose.yml config --format json | $(PYTHON) -m scripts.validate_resolved_compose

check: lint test compose-check resolved-check
