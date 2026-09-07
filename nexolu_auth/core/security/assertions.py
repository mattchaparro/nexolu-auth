"""Emision de aserciones SSO.

Una asercion es lo UNICO que este servicio emite hacia afuera: un JWT
firmado con RSA, de vida muy corta, dirigido a UN producto. El consumidor la
verifica localmente con la llave publica y la canjea por su credencial
nativa (un PAT de Sanctum en pos/spa, su propio token en el panel). Despues
del canje este servicio no vuelve a aparecer en ningun camino de request -
por eso la verificacion local no depende de la disciplina de nadie, es la
estructura del diseno.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

import jwt

from nexolu_auth.config import Product, get_settings
from nexolu_auth.core.db.entities import Identity
from nexolu_auth.core.security.keys import get_kid, get_private_key

ASSERTION_TYPE = "sso"


def mint_assertion(
    identity: Identity,
    product: Product,
    external_user_id: str | None = None,
) -> str:
    settings = get_settings()
    now = int(datetime.now(tz=UTC).timestamp())

    payload = {
        "iss": settings.auth_issuer,
        # UN solo producto, string y no lista: una asercion emitida para la
        # agenda no se puede canjear en el POS. Es la defensa central del
        # diseno (ver tests/test_assertion.py y el test equivalente en cada
        # consumidor).
        "aud": product.audience,
        "sub": identity.id,
        "iat": now,
        "nbf": now,
        "exp": now + settings.auth_assertion_ttl_seconds,
        "jti": uuid.uuid4().hex,
        "typ": ASSERTION_TYPE,
        "email": identity.email,
        "name": identity.full_name,
        # El consumidor resuelve por aca; el email es solo su fallback.
        "account": {"user_id": external_user_id} if external_user_id else None,
        # PISTA, nunca autoritativa: el canje del POS igual pregunta
        # hasRole('superadmin') y el de la agenda igual pregunta
        # is_super_admin. Este servicio dice QUIEN eres, no QUE puedes.
        # En la Fase 1 la unica identidad es el superadmin; cuando entren
        # mas, esto se deriva de la identidad en vez de ser constante.
        "scope": "superadmin",
    }

    return jwt.encode(
        payload,
        get_private_key(),
        algorithm="RS256",
        headers={"kid": get_kid()},
    )
