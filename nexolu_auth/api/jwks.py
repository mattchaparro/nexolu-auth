"""Publicacion de la llave publica.

Ningun consumidor llama esto en runtime: cada uno lleva la llave fijada en
su .env (ver core/security/keys.py para el porque). Este endpoint es como
la OBTIENES para pegarla, y es lo que hace barata la rotacion: publicas el
kid nuevo aca, lo pegas en los .env (ambas llaves conviven porque el .env
acepta un diccionario), y recien despues cambias la llave de firma.
"""
from __future__ import annotations

from fastapi import APIRouter

from nexolu_auth.core.security import keys

router = APIRouter(tags=["jwks"])


@router.get("/.well-known/jwks.json")
async def jwks() -> dict[str, list[dict[str, str]]]:
    return keys.jwks()
