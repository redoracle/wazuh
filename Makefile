.PHONY: help bootstrap bootstrap-check certs config check test up status logs down
PYTHON ?= python3

help:
	@printf '%s\n' 'make bootstrap  - create unique credentials (one time)' 'make certs      - generate TLS certificates (requires Docker)' 'make config     - verify interpolated Compose model' 'make test       - execute offline regression tests' 'make check      - run tests and Compose validation' 'make up         - start the stack' 'make status     - show service status' 'make logs       - follow service logs' 'make down       - stop services (keeps volumes)'

bootstrap:
	$(PYTHON) scripts/bootstrap.py

bootstrap-check:
	$(PYTHON) scripts/bootstrap.py --check

certs:
	docker compose -f generate-indexer-certs.yml run --rm generator

config:
	docker compose -f docker-compose.yml config --quiet

check: test config

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
