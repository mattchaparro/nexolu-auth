"""La sesion SSO del navegador en auth.nexolu.co.

Esto es lo que convierte "una sola contrasena" en "un solo login": mientras
la sesion viva, pedir una asercion para el segundo producto es un 302 sin
formulario.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nexolu_auth.config import get_settings
from nexolu_auth.core.db.entities import AuthSession, Identity

# Host-only en auth.nexolu.co, deliberadamente SIN Domain=.nexolu.co: eso la
# mandaria tambien a tienda.nexolu.co, donde navegan compradores anonimos.
COOKIE_NAME = "nexolu_auth_session"

# SameSite=Lax y no Strict: `Strict` no manda la cookie en una navegacion
# cross-site, que es exactamente lo que hace el rebote desde admin/pos/spa -
# con Strict el SSO silencioso no funcionaria y el sintoma seria "siempre me
# pide la contrasena", sin error en ningun lado.
COOKIE_SAMESITE = "lax"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def create_session(
    session: AsyncSession,
    identity: Identity,
    user_agent: str | None = None,
    ip: str | None = None,
) -> str:
    """Crea la sesion y devuelve el token EN CLARO (lo unico que ve el
    navegador). En la tabla solo queda su SHA-256."""
    token = secrets.token_urlsafe(32)
    ttl = timedelta(hours=get_settings().auth_session_ttl_hours)

    session.add(
        AuthSession(
            identity_id=identity.id,
            token_hash=_hash(token),
            user_agent=(user_agent or "")[:255] or None,
            ip=ip,
            expires_at=datetime.utcnow() + ttl,
        )
    )
    await session.commit()

    return token


async def resolve_session(session: AsyncSession, token: str | None) -> Identity | None:
    """Devuelve la identidad de una sesion viva, o None."""
    if not token:
        return None

    result = await session.execute(
        select(AuthSession).where(AuthSession.token_hash == _hash(token))
    )
    auth_session = result.scalar_one_or_none()

    if auth_session is None or auth_session.revoked_at is not None:
        return None

    if auth_session.expires_at <= datetime.utcnow():
        return None

    identity = await session.get(Identity, auth_session.identity_id)
    if identity is None or not identity.is_active:
        return None

    auth_session.last_used_at = datetime.utcnow()
    await session.commit()

    return identity


async def revoke_session(session: AsyncSession, token: str | None) -> None:
    if not token:
        return

    result = await session.execute(
        select(AuthSession).where(AuthSession.token_hash == _hash(token))
    )
    auth_session = result.scalar_one_or_none()

    if auth_session is not None and auth_session.revoked_at is None:
        auth_session.revoked_at = datetime.utcnow()
        await session.commit()


async def list_active(session: AsyncSession, identity_id: str) -> list[AuthSession]:
    result = await session.execute(
        select(AuthSession)
        .where(
            AuthSession.identity_id == identity_id,
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > datetime.utcnow(),
        )
        .order_by(AuthSession.created_at.desc())
    )
    return list(result.scalars())


def cookie_kwargs() -> dict[str, object]:
    """Los flags de la cookie, en un solo lugar para que el login y el
    logout no puedan divergir."""
    return {
        "httponly": True,
        "secure": get_settings().auth_cookie_secure,
        "samesite": COOKIE_SAMESITE,
        "path": "/",
        "max_age": get_settings().auth_session_ttl_hours * 3600,
    }
