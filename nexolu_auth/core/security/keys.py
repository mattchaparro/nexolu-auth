"""Llave de firma RSA y su publicacion como JWKS.

RS256 y no EdDSA por una razon concreta del otro lado: el runtime de
nexolu-pos-api es `php:8.4-fpm-alpine` con `openssl` garantizado por
Laravel, mientras que `sodium` (que EdDSA necesita) viene en la imagen pero
no esta declarado ni verificado en su Dockerfile. `ext-gd` se declaro en su
composer.json justamente porque una extension faltante se detecta tarde y en
produccion; no vale la pena repetir esa forma de fallo en el camino del
login.

La llave PUBLICA se publica aca como JWKS, pero ningun consumidor la
consulta en caliente: cada uno la lleva fijada en su .env. Un JWKS cacheado
igual tendria un primer fetch despues de cada reinicio de contenedor, y ese
fetch cae justo despues de un deploy - la misma forma del bug del
2026-08-20 que dejo al panel sin poder loguearse. El JWKS existe para que
puedas OBTENER la llave que vas a pegar, y para que rotar sea barato.
"""
from __future__ import annotations

import base64
import hashlib
from functools import lru_cache

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from nexolu_auth.config import get_settings


@lru_cache
def get_private_key() -> RSAPrivateKey:
    """La llave privada, cargada del .env. Lanza RuntimeError si falta."""
    key = serialization.load_pem_private_key(get_settings().private_key_pem, password=None)

    if not isinstance(key, RSAPrivateKey):
        # RuntimeError y no TypeError (TRY004): esto no es un llamador
        # pasando el tipo equivocado, es una variable de entorno mal
        # configurada. Todos los fallos de config de este servicio son
        # RuntimeError que NOMBRAN la variable, para que el mensaje apunte
        # solo al archivo que hay que arreglar.
        raise RuntimeError(  # noqa: TRY004
            "AUTH_JWT_PRIVATE_KEY no es una llave RSA (RS256 exige RSA)."
        )

    return key


def get_public_key() -> RSAPublicKey:
    return get_private_key().public_key()


def public_key_pem() -> str:
    return get_public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


@lru_cache
def get_kid() -> str:
    """Identificador de la llave.

    Si `AUTH_JWT_KID` esta puesto se respeta; si no, se deriva del propio
    material publico. Derivarlo hace que dos despliegues de la misma llave
    coincidan solos, y que dos llaves distintas nunca colisionen por
    descuido.
    """
    settings = get_settings()
    if settings.auth_jwt_kid:
        return settings.auth_jwt_kid

    der = get_public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()[:16]


def _b64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def public_jwk() -> dict[str, str]:
    numbers = get_public_key().public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": get_kid(),
        "n": _b64url_uint(numbers.n),
        "e": _b64url_uint(numbers.e),
    }


def jwks() -> dict[str, list[dict[str, str]]]:
    return {"keys": [public_jwk()]}
