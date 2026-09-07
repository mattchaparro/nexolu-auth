"""Limite de intentos de login, contra la tabla `login_attempts`.

Hoy no hay throttle en NINGUN login del ecosistema: ni en
`nexolu-pos-api/routes/api.php:213` ni en el del panel. Como este servicio
pasa a ser la puerta unica de una identidad que abre cuatro sistemas, el
limite deja de ser opcional.

Contra la base y no con una dependencia nueva: contar filas indexadas sale
gratis a este volumen, y de paso queda el rastro de auditoria de quien
intento entrar.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from nexolu_auth.config import get_settings
from nexolu_auth.core.db.entities import LoginAttempt


async def is_rate_limited(session: AsyncSession, email: str, ip: str | None) -> bool:
    """Se cuenta por IP *o* por correo.

    Por IP frena la fuerza bruta desde un origen; por correo frena la que se
    reparte entre muchos origenes contra una sola cuenta - que, con una sola
    identidad en el sistema, es el ataque que de verdad aplica.
    """
    settings = get_settings()
    since = datetime.utcnow() - timedelta(minutes=settings.auth_login_window_minutes)

    conditions = [LoginAttempt.email == email]
    if ip:
        conditions.append(LoginAttempt.ip == ip)

    for condition in conditions:
        result = await session.execute(
            select(func.count())
            .select_from(LoginAttempt)
            .where(
                condition,
                LoginAttempt.succeeded.is_(False),
                LoginAttempt.created_at >= since,
            )
        )
        if (result.scalar() or 0) >= settings.auth_login_max_attempts:
            return True

    return False


async def record_attempt(
    session: AsyncSession, email: str, ip: str | None, succeeded: bool
) -> None:
    session.add(LoginAttempt(email=email, ip=ip, succeeded=succeeded))
    await session.commit()
