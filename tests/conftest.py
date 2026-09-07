"""Fixtures compartidas.

`Settings`, el engine de BD y la llave de firma estan cacheados con
`lru_cache` (a proposito: son singletons de proceso en produccion). Para que
cada test corra aislado con su propio `DATABASE_URL` y su propia llave, este
fixture limpia esos caches antes y despues de cada test - mismo patron que
nexolu-comms-api.
"""
from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

TEST_EMAIL = "superadmin@nexolu.test"
TEST_PASSWORD = "una-clave-larga-y-buena"
TEST_PLATFORM_API_KEY = "platform-key"

# Un solo par RSA para toda la corrida: generar una llave de 2048 bits por
# test cuesta cientos de milisegundos y no aporta aislamiento (lo que hay
# que aislar es la BD, no el material criptografico).
_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PRIVATE_PEM = _PRIVATE_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
TEST_PRIVATE_KEY_B64 = base64.b64encode(_PRIVATE_PEM).decode()
TEST_PUBLIC_KEY = _PRIVATE_KEY.public_key()

TEST_PRODUCTS = {
    "nexolu-admin": {
        "name": "Panel de administracion",
        "audience": "nexolu-admin",
        "redirect_url": "https://admin.nexolu.test/iniciar-sesion",
    },
    "nexolu-pos-api": {
        "name": "Nexolu POS",
        "audience": "nexolu-pos-api",
        "redirect_url": "https://pos.nexolu.test/iniciar-sesion",
    },
}


@pytest.fixture(autouse=True)
def app_env(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
    monkeypatch.setenv("AUTH_ISSUER", "https://auth.nexolu.test")
    monkeypatch.setenv("AUTH_JWT_PRIVATE_KEY", TEST_PRIVATE_KEY_B64)
    monkeypatch.setenv("AUTH_JWT_KID", "")
    monkeypatch.setenv("AUTH_PRODUCTS_JSON", json.dumps(TEST_PRODUCTS))
    monkeypatch.setenv("NEXOLU_PLATFORM_API_KEY", TEST_PLATFORM_API_KEY)
    # TestClient habla http://testserver: una cookie `Secure` no volveria
    # nunca y todo el SSO se veria roto por una razon que no es la real.
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "false")

    _clear_caches()
    yield
    _clear_caches()


def _clear_caches() -> None:
    from nexolu_auth.config import get_settings
    from nexolu_auth.core.db.session import get_engine, get_sessionmaker
    from nexolu_auth.core.security.keys import get_kid, get_private_key

    get_settings.cache_clear()
    get_engine.cache_clear()
    get_sessionmaker.cache_clear()
    get_private_key.cache_clear()
    get_kid.cache_clear()


@pytest.fixture
def client(app_env):
    from nexolu_auth.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client


@pytest.fixture
async def seed(app_env):
    """Escribe en la BD con un engine DESECHABLE, no con el cacheado.

    El engine de `get_engine()` es un `lru_cache` cuyas conexiones quedan en
    un pool atado al event loop que las creo. Si esta fixture (loop de
    pytest-asyncio) y el `TestClient` (su propio portal anyio) compartieran
    ese pool, aiosqlite reventaria con "attached to a different loop" de
    forma intermitente. Crear y desechar un engine propio lo evita de raiz.
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from nexolu_auth.config import get_settings
    from nexolu_auth.core.db.session import Base

    engine = create_async_engine(get_settings().database_url)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    maker = async_sessionmaker(engine, expire_on_commit=False)

    async def _write(fn):
        async with maker() as session:
            result = await fn(session)
            await session.commit()
            return result

    yield _write

    await engine.dispose()


@pytest.fixture
async def identity(seed):
    """La identidad de pruebas, con vinculo a los dos productos."""
    from nexolu_auth.core.db.entities import Credential, Identity, LinkedAccount
    from nexolu_auth.core.security.passwords import hash_password

    async def _create(session):
        row = Identity(email=TEST_EMAIL, full_name="Super Admin", is_active=True)
        session.add(row)
        await session.flush()

        session.add(
            Credential(identity_id=row.id, type="password", secret=hash_password(TEST_PASSWORD))
        )
        session.add(
            LinkedAccount(identity_id=row.id, product="nexolu-pos-api", external_user_id="1")
        )
        session.add(
            LinkedAccount(identity_id=row.id, product="nexolu-admin", external_user_id="1")
        )

        return {"id": row.id, "email": row.email}

    return await seed(_create)


@pytest.fixture
def logged_in(client, identity):
    """Cliente con la cookie de sesion SSO ya puesta."""
    response = client.post(
        "/v1/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD}
    )
    assert response.status_code == 200, response.text
    return client
