"""Resolucion y autenticacion de identidades."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from nexolu_auth.core.db.entities import Credential, Identity, LinkedAccount
from nexolu_auth.core.security.passwords import verify_password

PASSWORD = "password"


def normalize_email(email: str) -> str:
    """El correo es la llave natural del login y del fallback de los
    consumidores. Normalizarlo en UN solo lugar evita el 403 silencioso de
    que `Matt@...` y `matt@...` sean identidades distintas."""
    return email.strip().lower()


async def get_by_email(session: AsyncSession, email: str) -> Identity | None:
    result = await session.execute(
        select(Identity).where(Identity.email == normalize_email(email))
    )
    return result.scalar_one_or_none()


async def authenticate(session: AsyncSession, email: str, password: str) -> Identity | None:
    """Devuelve la identidad si las credenciales son correctas, o None.

    Un solo None para todos los casos (correo desconocido, contrasena
    equivocada, identidad desactivada, credencial desactivada): quien llama
    responde un mensaje generico unico, mismo criterio que el login del
    panel. Distinguirlos le diria a un atacante que correos existen.
    """
    identity = await get_by_email(session, email)
    if identity is None or not identity.is_active:
        return None

    result = await session.execute(
        select(Credential).where(
            Credential.identity_id == identity.id,
            Credential.type == PASSWORD,
        )
    )
    credential = result.scalar_one_or_none()

    if credential is None or not credential.is_active:
        return None

    if not verify_password(password, credential.secret):
        return None

    return identity


async def get_linked_account(
    session: AsyncSession, identity_id: str, product_slug: str
) -> LinkedAccount | None:
    result = await session.execute(
        select(LinkedAccount).where(
            LinkedAccount.identity_id == identity_id,
            LinkedAccount.product == product_slug,
            LinkedAccount.is_active.is_(True),
        )
    )
    return result.scalar_one_or_none()


async def list_linked_accounts(session: AsyncSession, identity_id: str) -> list[LinkedAccount]:
    result = await session.execute(
        select(LinkedAccount).where(LinkedAccount.identity_id == identity_id)
    )
    return list(result.scalars())
