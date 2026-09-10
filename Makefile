.PHONY: install install-dev dev seed test test-cov lint format run docker-up docker-down demo clean verify

PY ?= python3
API ?= http://127.0.0.1:8000

install: ## Install minimal runtime deps (edge / Termux friendly)
	$(PY) -m pip install -r requirements-minimal.txt

install-dev: ## Install runtime + dev/test tooling
	$(PY) -m pip install -r requirements-minimal.txt -r requirements-dev.txt

install-prod: ## Install full production deps (includes ML + cloud SDKs)
	$(PY) -m pip install -r requirements-prod.txt

dev: ## Run API with auto-reload
	PYTHONPATH=. $(PY) -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

run: ## Run API (production-ish, no reload)
	PYTHONPATH=. $(PY) -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000

seed: ## Seed the statutory (BNS/IT Act) knowledge base
	PYTHONPATH=. $(PY) seed_legal_db.py

test: ## Run test suite
	PYTHONPATH=. $(PY) -m pytest

test-cov: ## Run tests with coverage report
	PYTHONPATH=. $(PY) -m pytest --cov=src --cov-report=term-missing 2>/dev/null || PYTHONPATH=. $(PY) -m pytest

lint: ## Ruff lint check
	$(PY) -m ruff check src tests netra_cli.py seed_legal_db.py 2>/dev/null || echo "ruff not installed (pip install -r requirements-dev.txt)"

format: ## Ruff format (in place)
	$(PY) -m ruff format src tests netra_cli.py 2>/dev/null || echo "ruff not installed"

verify: ## Verify evidence chain demo (needs a case first — see demo)
	PYTHONPATH=. $(PY) tamper_test.py

demo: ## End-to-end demo: seed + intake a network case via CLI (server must run)
	$(PY) netra_cli.py intake --api $(API) --agent demo-op --case CASE-DEMO-001 --target network \
		--evidence "beacon to 203.0.113.45 and c2-server.example" --priority HIGH \
		--warrant W-DEMO-1 --issued-by "Demo Court" --expires 2026-12-31T23:59:59Z

docker-up: ## Start full stack (API + Postgres + Redis)
	docker compose up -d --build

docker-down: ## Stop stack
	docker compose down

clean: ## Remove caches and generated artifacts (keeps evidence vault)
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null; \
	rm -rf .pytest_cache .ruff_cache site .coverage
