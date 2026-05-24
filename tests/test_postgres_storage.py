from __future__ import annotations

import asyncio
import os
from uuid import uuid4

import pytest

pytest.importorskip("sqlalchemy")

from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateIndex, CreateTable

from coreline_auth import AsyncCorelineAuthService, AuthProfile, CorelineAuthConfig
from coreline_auth.storage.postgres import AsyncPostgresAuthStorage
from coreline_auth.storage.sqlalchemy_schema import metadata


def test_sqlalchemy_schema_compiles_for_postgres() -> None:
    dialect = postgresql.dialect()
    ddl = "\n".join(str(CreateTable(table).compile(dialect=dialect)) for table in metadata.sorted_tables)
    index_ddl = "\n".join(str(CreateIndex(index).compile(dialect=dialect)) for table in metadata.sorted_tables for index in table.indexes)

    assert "CREATE TABLE auth_users" in ddl
    assert "JSONB" in ddl
    assert "uq_auth_password_credential_active" in index_ddl
    assert "WHERE credential_type = 'password' AND revoked_at IS NULL" in index_ddl


def test_async_postgres_storage_can_be_constructed_without_connecting() -> None:
    storage = AsyncPostgresAuthStorage("postgresql+asyncpg://user:pass@127.0.0.1:5432/coreline_auth_test")
    assert storage.engine is not None
    asyncio.run(storage.close())


@pytest.mark.skipif(not os.getenv("CORELINE_AUTH_POSTGRES_DSN"), reason="CORELINE_AUTH_POSTGRES_DSN not set")
def test_async_postgres_auth_core_flow_smoke() -> None:
    async def scenario() -> None:
        storage = AsyncPostgresAuthStorage(os.environ["CORELINE_AUTH_POSTGRES_DSN"])
        await storage.bootstrap()
        try:
            service = AsyncCorelineAuthService(storage=storage, config=CorelineAuthConfig(profile=AuthProfile.RBAC, require_email_verified=False))
            email = f"pg-{uuid4().hex}@example.com"
            await service.create_user(email=email, password="correct horse battery", email_verified=True)
            issued = await service.login_password(email=email, password="correct horse battery")
            assert (await service.verify_session(issued.token)).email == email
            await service.logout(issued.token)
        finally:
            await storage.close()

    asyncio.run(scenario())


def test_alembic_script_directory_has_initial_revision() -> None:
    alembic_config = pytest.importorskip("alembic.config")
    alembic_script = pytest.importorskip("alembic.script")

    project_root = os.path.dirname(os.path.dirname(__file__))
    config = alembic_config.Config(os.path.join(project_root, "alembic.ini"))
    script = alembic_script.ScriptDirectory.from_config(config)

    assert script.get_current_head() == "0001_initial"

