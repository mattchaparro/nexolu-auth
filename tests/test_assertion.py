from __future__ import annotations

import jwt
import pytest

from tests.conftest import TEST_EMAIL, TEST_PUBLIC_KEY

ISSUER = "https://auth.nexolu.test"


def decode(assertion: str, audience: str) -> dict:
    return jwt.decode(
        assertion,
        TEST_PUBLIC_KEY,
        algorithms=["RS256"],
        audience=audience,
        issuer=ISSUER,
    )


def emitir(client, product: str) -> str:
    response = client.post("/v1/auth/authorize", json={"product": product})
    assert response.status_code == 200, response.text
    return response.json()["assertion"]


def test_la_asercion_verifica_con_la_llave_publica(logged_in):
    claims = decode(emitir(logged_in, "nexolu-pos-api"), "nexolu-pos-api")

    assert claims["iss"] == ISSUER
    assert claims["typ"] == "sso"
    assert claims["email"] == TEST_EMAIL


def test_audience_es_el_producto_pedido(logged_in):
    claims = decode(emitir(logged_in, "nexolu-admin"), "nexolu-admin")

    assert claims["aud"] == "nexolu-admin"


def test_una_asercion_de_un_producto_no_sirve_en_otro(logged_in):
    """La defensa central del diseno. Cada consumidor tiene el test espejo
    de este: una asercion emitida para la agenda presentada al POS es 401."""
    para_admin = emitir(logged_in, "nexolu-admin")

    with pytest.raises(jwt.InvalidAudienceError):
        decode(para_admin, "nexolu-pos-api")


def test_ttl_de_120_segundos(logged_in):
    claims = decode(emitir(logged_in, "nexolu-pos-api"), "nexolu-pos-api")

    assert claims["exp"] - claims["iat"] == 120
    assert claims["nbf"] == claims["iat"]


def test_jti_distinto_en_cada_emision(logged_in):
    primera = decode(emitir(logged_in, "nexolu-pos-api"), "nexolu-pos-api")
    segunda = decode(emitir(logged_in, "nexolu-pos-api"), "nexolu-pos-api")

    assert primera["jti"] != segunda["jti"]


def test_account_sale_de_linked_accounts(logged_in):
    claims = decode(emitir(logged_in, "nexolu-pos-api"), "nexolu-pos-api")

    assert claims["account"] == {"user_id": "1"}


def test_sub_es_el_id_de_la_identidad(logged_in, identity):
    claims = decode(emitir(logged_in, "nexolu-pos-api"), "nexolu-pos-api")

    assert claims["sub"] == identity["id"]


async def test_sin_vinculo_el_account_va_nulo(logged_in, identity, seed):
    """El consumidor cae entonces a su fallback por correo, y su log tiene
    que decir por cual de los dos caminos resolvio."""
    from sqlalchemy import delete

    from nexolu_auth.core.db.entities import LinkedAccount

    async def _borrar(session):
        await session.execute(
            delete(LinkedAccount).where(LinkedAccount.product == "nexolu-pos-api")
        )

    await seed(_borrar)

    claims = decode(emitir(logged_in, "nexolu-pos-api"), "nexolu-pos-api")
    assert claims["account"] is None


def test_authorize_exige_sesion(client, identity):
    assert client.post("/v1/auth/authorize", json={"product": "nexolu-pos-api"}).status_code == 401


def test_authorize_rechaza_producto_desconocido(logged_in):
    assert (
        logged_in.post("/v1/auth/authorize", json={"product": "no-existe"}).status_code == 400
    )


def test_scope_no_es_autoritativo(logged_in):
    """Va como pista y nada mas: el canje del POS igual pregunta
    hasRole('superadmin') y el de la agenda igual pregunta is_super_admin."""
    claims = decode(emitir(logged_in, "nexolu-pos-api"), "nexolu-pos-api")

    assert claims["scope"] == "superadmin"
