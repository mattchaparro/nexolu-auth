from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization

from tests.conftest import TEST_PUBLIC_KEY


def test_jwks_es_publico(client):
    """Sin auth a proposito: es la llave publica, y es como la obtienes para
    pegarla en el .env de cada consumidor."""
    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200
    assert len(response.json()["keys"]) == 1


def test_jwks_tiene_la_forma_esperada(client):
    key = client.get("/.well-known/jwks.json").json()["keys"][0]

    assert key["kty"] == "RSA"
    assert key["use"] == "sig"
    assert key["alg"] == "RS256"
    assert key["kid"]
    assert key["n"]
    assert key["e"]


def test_jwks_publica_la_llave_de_firma_real(client):
    """El JWKS tiene que ser la MISMA llave con la que se firma, no otra
    derivada por accidente de otra fuente."""
    key = client.get("/.well-known/jwks.json").json()["keys"][0]

    def _decode(value: str) -> int:
        padded = value + "=" * (-len(value) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(padded), "big")

    numbers = TEST_PUBLIC_KEY.public_numbers()
    assert _decode(key["n"]) == numbers.n
    assert _decode(key["e"]) == numbers.e


def test_kid_coincide_con_el_header_de_la_asercion(client, logged_in):
    import jwt

    key = client.get("/.well-known/jwks.json").json()["keys"][0]
    assertion = logged_in.post(
        "/v1/auth/authorize", json={"product": "nexolu-pos-api"}
    ).json()["assertion"]

    assert jwt.get_unverified_header(assertion)["kid"] == key["kid"]


def test_kid_se_deriva_del_material_publico(client):
    """Sin AUTH_JWT_KID puesto, el kid sale del sha256 del DER publico: dos
    despliegues de la misma llave coinciden solos y dos llaves distintas no
    pueden colisionar por descuido."""
    import hashlib

    der = TEST_PUBLIC_KEY.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    esperado = hashlib.sha256(der).hexdigest()[:16]

    assert client.get("/.well-known/jwks.json").json()["keys"][0]["kid"] == esperado
