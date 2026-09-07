"""El servicio tiene que fallar cerrado y NOMBRANDO la variable.

El modo de falla mas probable de todo el despliegue es un PEM mal pegado en
un .env: es multilinea por naturaleza y un .env es de una linea. Si eso
resultara en un error generico, el sintoma seria "todos los canjes fallan" y
la causa estaria a varias horas de distancia.
"""
from __future__ import annotations

import pytest

from nexolu_auth.config import get_settings
from nexolu_auth.core.security.keys import get_kid, get_private_key


def _reset() -> None:
    get_settings.cache_clear()
    get_private_key.cache_clear()
    get_kid.cache_clear()


def test_llave_privada_vacia_nombra_la_variable(monkeypatch):
    monkeypatch.setenv("AUTH_JWT_PRIVATE_KEY", "")
    _reset()

    with pytest.raises(RuntimeError, match="AUTH_JWT_PRIVATE_KEY"):
        get_private_key()


def test_llave_privada_no_base64_nombra_la_variable(monkeypatch):
    monkeypatch.setenv("AUTH_JWT_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----\nrota\n")
    _reset()

    with pytest.raises(RuntimeError, match="AUTH_JWT_PRIVATE_KEY"):
        get_private_key()


def test_productos_vacios_no_reventan(monkeypatch):
    monkeypatch.setenv("AUTH_PRODUCTS_JSON", "{}")
    _reset()

    assert get_settings().products == {}


def test_kid_explicito_gana_sobre_el_derivado(monkeypatch):
    monkeypatch.setenv("AUTH_JWT_KID", "kid-a-mano")
    _reset()

    assert get_kid() == "kid-a-mano"


def test_platform_api_key_vacia_da_503(client, monkeypatch):
    """Mismo idioma que `require_platform_access` en los otros servicios:
    sin la key configurada el endpoint no existe operativamente, y eso es un
    503 y no un 401."""
    from nexolu_auth.core.auth.dependencies import require_platform_access

    monkeypatch.setenv("NEXOLU_PLATFORM_API_KEY", "")
    _reset()

    import asyncio

    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        asyncio.run(require_platform_access(authorization="Bearer lo-que-sea"))

    assert exc.value.status_code == 503
