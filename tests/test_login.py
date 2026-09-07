from __future__ import annotations

import bcrypt
import pytest

from tests.conftest import TEST_EMAIL, TEST_PASSWORD

MENSAJE_GENERICO = "Correo o contrasena incorrectos."


def test_login_correcto(client, identity):
    response = client.post(
        "/v1/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD}
    )

    assert response.status_code == 200
    assert response.json()["identity"]["email"] == TEST_EMAIL


def test_login_deja_la_cookie_de_sesion(client, identity):
    from nexolu_auth.core.auth.sessions import COOKIE_NAME

    response = client.post(
        "/v1/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD}
    )

    assert COOKIE_NAME in response.cookies


def test_login_devuelve_las_cuentas_vinculadas(client, identity):
    cuentas = client.post(
        "/v1/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD}
    ).json()["identity"]["linked_accounts"]

    por_producto = {c["product"]: c["external_user_id"] for c in cuentas}
    assert por_producto == {"nexolu-pos-api": "1", "nexolu-admin": "1"}


def test_email_insensible_a_mayusculas(client, identity):
    """Un desfase de mayusculas aca seria un 403 silencioso en el consumidor
    que hace fallback por correo."""
    response = client.post(
        "/v1/auth/login", json={"email": TEST_EMAIL.upper(), "password": TEST_PASSWORD}
    )

    assert response.status_code == 200


@pytest.mark.parametrize(
    "payload",
    [
        {"email": TEST_EMAIL, "password": "equivocada"},
        {"email": "nadie@nexolu.test", "password": TEST_PASSWORD},
    ],
    ids=["contrasena_mala", "correo_desconocido"],
)
def test_credenciales_invalidas_dan_el_mismo_mensaje(client, identity, payload):
    """Un solo mensaje para todos los fallos: distinguirlos le diria a un
    atacante que correos existen."""
    response = client.post("/v1/auth/login", json=payload)

    assert response.status_code == 401
    assert response.json()["detail"] == MENSAJE_GENERICO


async def test_identidad_desactivada_no_entra(client, identity, seed):
    from sqlalchemy import update

    from nexolu_auth.core.db.entities import Identity

    async def _desactivar(session):
        await session.execute(
            update(Identity).where(Identity.id == identity["id"]).values(is_active=False)
        )

    await seed(_desactivar)

    response = client.post(
        "/v1/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD}
    )

    assert response.status_code == 401
    assert response.json()["detail"] == MENSAJE_GENERICO


async def test_credencial_desactivada_no_entra(client, identity, seed):
    from sqlalchemy import update

    from nexolu_auth.core.db.entities import Credential

    async def _desactivar(session):
        await session.execute(
            update(Credential)
            .where(Credential.identity_id == identity["id"])
            .values(is_active=False)
        )

    await seed(_desactivar)

    assert (
        client.post(
            "/v1/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD}
        ).status_code
        == 401
    )


async def test_acepta_hash_2y_de_laravel(client, seed):
    """El supuesto sobre el que descansa TODA la decision de sembrar
    copiando el hash de `pos_saas.users#1` en vez de fijar una contrasena
    nueva. Laravel emite `$2y$`; python-bcrypt lo acepta sin conversion."""
    from nexolu_auth.core.db.entities import Credential, Identity

    clave = "la-clave-de-siempre"
    hash_2b = bcrypt.hashpw(clave.encode(), bcrypt.gensalt(rounds=12))
    hash_2y = hash_2b.replace(b"$2b$", b"$2y$").decode()

    assert hash_2y.startswith("$2y$")

    async def _crear(session):
        row = Identity(email="laravel@nexolu.test", full_name="Desde Laravel", is_active=True)
        session.add(row)
        await session.flush()
        session.add(Credential(identity_id=row.id, type="password", secret=hash_2y))

    await seed(_crear)

    response = client.post(
        "/v1/auth/login", json={"email": "laravel@nexolu.test", "password": clave}
    )

    assert response.status_code == 200


def test_rate_limit_tras_cinco_fallos(client, identity):
    """Hoy no hay throttle en NINGUN login del ecosistema. Como este
    servicio pasa a ser la puerta unica de cuatro sistemas, el limite deja
    de ser opcional."""
    for _ in range(5):
        assert (
            client.post(
                "/v1/auth/login", json={"email": TEST_EMAIL, "password": "equivocada"}
            ).status_code
            == 401
        )

    bloqueado = client.post(
        "/v1/auth/login", json={"email": TEST_EMAIL, "password": "equivocada"}
    )
    assert bloqueado.status_code == 429

    # Y bloquea incluso con la contrasena correcta: si no, el limite no
    # frenaria una fuerza bruta que acierta en el intento 6.
    con_la_buena = client.post(
        "/v1/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD}
    )
    assert con_la_buena.status_code == 429
