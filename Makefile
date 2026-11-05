PYTHON ?= python3
COMPOSE ?= docker compose
COMPOSE_FILE ?= docker-compose.yml

.PHONY: test compose-check check

test:
	$(PYTHON) -m unittest discover -s tests -v

compose-check:
	$(COMPOSE) -f $(COMPOSE_FILE) config --quiet

check: test compose-check
