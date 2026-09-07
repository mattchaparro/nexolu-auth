from __future__ import annotations

from tests.conftest import TEST_EMAIL, TEST_PASSWORD


def _set_cookie_header(response) -> str:
    return response.headers["set-cookie"]


def test_la_cookie_es_httponly_y_samesite_lax(client, identity, monkeypatch):
    """Lax y no Strict: `Strict` no manda la cookie en una navegacion
    cross-site, que es exactamente lo que hace el rebote desde
    admin/pos/spa. Con Strict el SSO silencioso no funcionaria y el sintoma
    seria "siempre me pide la contrasena", sin error en ningun lado."""
    response = client.post(
        "/v1/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD}
    )

    cabecera = _set_cookie_header(response).lower()
    assert "httponly" in cabecera
    assert "samesite=lax" in cabecera
    assert "path=/" in cabecera
    # Sin Domain=: host-only en auth.nexolu.co. Con Domain=.nexolu.co la
    # cookie viajaria tambien a tienda.nexolu.co, donde navegan compradores
    # anonimos.
    assert "domain=" not in cabecera


def test_la_cookie_es_secure_en_produccion(client, identity, monkeypatch):
    from nexolu_auth.config import get_settings

    monkeypatch.setenv("AUTH_COOKIE_SECURE", "true")
    get_settings.cache_clear()

    response = client.post(
        "/v1/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD}
    )

    assert "secure" in _set_cookie_header(response).lower()


def test_me_requiere_sesion(client, identity):
    assert client.get("/v1/auth/me").status_code == 401


def test_me_con_sesion(logged_in, identity):
    response = logged_in.get("/v1/auth/me")

    assert response.status_code == 200
    assert response.json()["id"] == identity["id"]


def test_sessions_lista_la_activa(logged_in):
    response = logged_in.get("/v1/auth/sessions")

    assert response.status_code == 200
    assert len(response.json()) == 1


async def test_logout_revoca_la_sesion(logged_in, seed):
    from sqlalchemy import select

    from nexolu_auth.core.db.entities import AuthSession

    assert logged_in.post("/v1/auth/logout").status_code == 204

    async def _leer(session):
        result = await session.execute(select(AuthSession))
        return [row.revoked_at for row in result.scalars()]

    revocadas = await seed(_leer)
    assert len(revocadas) == 1
    assert revocadas[0] is not None


async def test_una_sesion_revocada_no_emite_aserciones(logged_in, seed):
    """El logout tiene que cortar el SSO de verdad, no solo borrar la cookie
    del navegador que la pidio."""
    from datetime import datetime

    from sqlalchemy import update

    from nexolu_auth.core.db.entities import AuthSession

    async def _revocar(session):
        await session.execute(update(AuthSession).values(revoked_at=datetime.utcnow()))

    await seed(_revocar)

    assert (
        logged_in.post("/v1/auth/authorize", json={"product": "nexolu-pos-api"}).status_code
        == 401
    )


async def test_una_sesion_vencida_no_emite_aserciones(logged_in, seed):
    from datetime import datetime, timedelta

    from sqlalchemy import update

    from nexolu_auth.core.db.entities import AuthSession

    async def _vencer(session):
        await session.execute(
            update(AuthSession).values(expires_at=datetime.utcnow() - timedelta(seconds=1))
        )

    await seed(_vencer)

    assert (
        logged_in.post("/v1/auth/authorize", json={"product": "nexolu-pos-api"}).status_code
        == 401
    )


def test_cookie_invalida_no_da_sesion(client, identity):
    from nexolu_auth.core.auth.sessions import COOKIE_NAME

    client.cookies.set(COOKIE_NAME, "no-es-un-token-real")

    assert client.get("/v1/auth/me").status_code == 401
