.PHONY: test import-guard readiness-check run-demo smoke-demo run-demo-board smoke-demo-board smoke-demo-secure secret-grep postgres-smoke postgres-migration-sql postgres-docker-smoke

BOARD_DEMO_PORT ?= 8011
BOARD_DEMO_PREFIX ?= /demo-board
BOARD_DEMO_DB ?= .coreline-auth-demo/board-rbac.sqlite3
BOARD_DEMO_AUTH_DB ?= .coreline-auth-demo/board-rbac-auth.sqlite3

test:
	uv run pytest -q
	uv run python -c "import coreline_auth; print('import-ok')"
	! grep -RIn "CoreMCP\|coremcp\|coreline_board\|coreline_board_saas" src/coreline_auth

import-guard:
	! grep -RIn "CoreMCP\|coremcp\|coreline_board\|coreline_board_saas" src/coreline_auth
	PYTHONPATH=src uv run pytest -q tests/test_import_boundaries.py

readiness-check:
	uv run python -m coreline_auth.ops_readiness

run-demo:
	uv run uvicorn coreline_auth.examples.saas_app:app --reload --port 8010

smoke-demo:
	uv run pytest -q tests/test_demo_webapp.py

run-demo-board:
	CORELINE_BOARD_DEMO_PREFIX="$(BOARD_DEMO_PREFIX)" CORELINE_BOARD_DEMO_DB="$(BOARD_DEMO_DB)" CORELINE_BOARD_DEMO_AUTH_DB="$(BOARD_DEMO_AUTH_DB)" PYTHONPATH=.:src uv run uvicorn demos.board_rbac.app:app --reload --port $(BOARD_DEMO_PORT)

smoke-demo-board:
	PYTHONPATH=.:src uv run pytest -q tests/demos

smoke-demo-secure:
	CORELINE_AUTH_DEMO_MODE=false uv run pytest -q tests/test_fastapi_adapter.py::test_csrf_protector_blocks_cookie_post_but_allows_bearer_opt_out tests/test_demo_webapp.py::test_demo_mode_off_hides_owner_password_and_debug_tokens tests/test_admin_api.py::test_admin_audit_api_requires_audit_read_and_redacts_metadata
	$(MAKE) secret-grep

secret-grep:
	! grep -RIn "raw-access-token\|raw-refresh-token\|raw-id-token\|coreline-demo-password" src/coreline_auth --exclude-dir=__pycache__

postgres-smoke:
	uv run --extra postgres pytest -q tests/test_postgres_storage.py

postgres-migration-sql:
	uv run --extra postgres alembic -c alembic.ini upgrade head --sql > /tmp/coreline-auth-alembic.sql
	grep -Eq "CREATE TABLE auth_users" /tmp/coreline-auth-alembic.sql
	grep -Eq "CREATE TABLE auth_sessions" /tmp/coreline-auth-alembic.sql
	grep -Eq "INSERT INTO alembic_version" /tmp/coreline-auth-alembic.sql
	@echo "alembic-offline-ok: /tmp/coreline-auth-alembic.sql"

postgres-docker-smoke:
	@NAME="coreline-auth-pg-smoke-$$$$"; \
	cleanup() { docker rm -f "$$NAME" >/dev/null 2>&1 || true; }; \
	trap cleanup EXIT INT TERM; \
	docker run -d --name "$$NAME" -e POSTGRES_USER=coreline_auth -e POSTGRES_PASSWORD=coreline_auth -e POSTGRES_DB=coreline_auth_smoke -p "127.0.0.1::5432" postgres:16-alpine >/dev/null; \
	PORT="$$(docker port "$$NAME" 5432/tcp | sed 's/.*://')"; \
	echo "postgres-port=$$PORT"; \
	i=0; \
	while [ $$i -lt 60 ]; do \
		if docker exec "$$NAME" pg_isready -U coreline_auth -d coreline_auth_smoke >/dev/null 2>&1; then break; fi; \
		i=$$((i + 1)); sleep 1; \
	done; \
	CORELINE_AUTH_POSTGRES_DSN="postgresql+asyncpg://coreline_auth:coreline_auth@127.0.0.1:$$PORT/coreline_auth_smoke" uv run --extra postgres alembic -c alembic.ini upgrade head; \
	CORELINE_AUTH_POSTGRES_DSN="postgresql+asyncpg://coreline_auth:coreline_auth@127.0.0.1:$$PORT/coreline_auth_smoke" uv run --extra postgres pytest -q tests/test_postgres_storage.py
