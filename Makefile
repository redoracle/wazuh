.PHONY: help bootstrap bootstrap-check certs config check test ai-test ai-config preflight docs-check cert-check up status logs down
PYTHON ?= python3

help:
	@printf '%s\n' 'make bootstrap  - create unique credentials (one time)' 'make certs      - generate TLS certificates (requires Docker)' 'make config     - verify interpolated Compose model' 'make test       - execute offline regression tests' 'make check      - run tests and Compose validation' 'make up         - start the stack' 'make status     - show service status' 'make logs       - follow service logs' 'make down       - stop services (keeps volumes)' 'make docs-check - verify local documentation links (offline)' 'make cert-check - verify TLS cert expiry, trust, key pairs and modes (host)' 

bootstrap:
	$(PYTHON) scripts/bootstrap.py

bootstrap-check:
	$(PYTHON) scripts/bootstrap.py --check

certs:
	docker compose -f generate-indexer-certs.yml run --rm generator

config:
	docker compose -f docker-compose.yml config --quiet

check: test config docs-check

test:
	$(PYTHON) -m unittest discover -s tests -v

up:
	docker compose up -d

status:
	docker compose ps

logs:
	docker compose logs -f --tail=100

down:
	docker compose down

# Does not start containers or contact any inference provider.
ai-test:
	$(PYTHON) -m unittest discover -s tests -p 'test_ai_*.py' -v

# Validates opt-in Compose overlay; run after one-time bootstrap.
ai-config:
	docker compose -f docker-compose.yml -f docker-compose.ai.yml config --quiet

# Static, read-only checks. Requires requirements-dev.txt (PyYAML).
preflight:
	$(PYTHON) scripts/enterprise_preflight.py --profile controlled

# Offline, dependency-free check for local Markdown links and heading anchors.
docs-check:
	$(PYTHON) scripts/check_docs.py

# Operator-only host security check, after generating TLS materials (needs openssl).
cert-check:
	$(PYTHON) scripts/check_certificates.py --min-days 30
