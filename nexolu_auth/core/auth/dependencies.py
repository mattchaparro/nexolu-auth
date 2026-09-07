"""Dependencias de FastAPI.

Dos sujetos distintos:

- La PERSONA, autenticada por la cookie de sesion SSO. Es quien pide
  aserciones para entrar a los productos.
- La PLATAFORMA, autenticada por `NEXOLU_PLATFORM_API_KEY`, para los
  endpoints de administracion. Puerto directo de
  `nexolu_comms_api/core/auth/dependencies.py`.
"""
from __future__ import annotations

import hmac

from fastapi import Cookie, Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from nexolu_auth.config import get_settings
from nexolu_auth.core.auth import sessions
from nexolu_auth.core.db.entities import Identity
from nexolu_auth.core.db.session import get_session


async def get_current_identity(
    nexolu_auth_session: str | None = Cookie(default=None),
    session: AsyncSession = Depends(get_session),
) -> Identity:
    identity = await sessions.resolve_session(session, nexolu_auth_session)

    if identity is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No hay una sesion activa.",
        )

    return identity


async def require_platform_access(authorization: str | None = Header(default=None)) -> None:
    settings = get_settings()

    if not settings.nexolu_platform_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="El acceso de plataforma no esta configurado (falta NEXOLU_PLATFORM_API_KEY).",
        )

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Falta el header Authorization."
        )

    api_key = authorization.split(" ", 1)[1].strip()

    # Comparacion de tiempo constante: esta key administra identidades,
    # vale la pena cerrar el timing side-channel.
    if not hmac.compare_digest(api_key, settings.nexolu_platform_api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="API key de plataforma invalida."
        )
