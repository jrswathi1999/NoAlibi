# No Alibi: make setup | make app | make test
PYTHON ?= python3.11
VENV ?= .venv
PY := $(VENV)/bin/python

.PHONY: setup app test format cdn-ranges

setup:
	$(PYTHON) -m venv $(VENV)
	$(PY) -m pip install -r requirements.txt
	@test -f .env || cp .env.example .env
	@echo "Setup done. Put your keys in .env (never commit it)."

app:
	$(PY) -m app

cdn-ranges:
	$(PY) scripts/update_cdn_ranges.py

test:
	@# exit code 5 means "no tests collected", which is fine early on
	$(PY) -m pytest -q || [ $$? -eq 5 ]

format:
	$(VENV)/bin/ruff format app engine intel report sensor contracts scripts tests --exclude tests/test_behavior.py
