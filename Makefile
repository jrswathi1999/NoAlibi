# No Alibi: make setup | make test | make audit APP="NotesApp" CMD="notesapp"
PYTHON ?= python3.11
VENV ?= .venv
PY := $(VENV)/bin/python

APP ?=
CMD ?=

.PHONY: setup test audit format offline serve

setup:
	$(PYTHON) -m venv $(VENV)
	$(PY) -m pip install -r requirements.txt
	@test -f .env || cp .env.example .env
	@echo "Setup done. Put your keys in .env (never commit it)."

test:
	@# exit code 5 means "no tests collected", which is fine early on
	$(PY) -m pytest -q || [ $$? -eq 5 ]

format:
	$(VENV)/bin/ruff format .

audit:
	@test -n "$(APP)" || (echo 'usage: make audit APP="<app name>" CMD="<app cmd>"' && exit 2)
	./scripts/run_audit.sh "$(APP)" "$(CMD)"

offline:
	./scripts/run_audit.sh --offline "$(or $(APP),NotesApp)"

serve:
	$(PY) -m uvicorn app.main:app --port 8000
