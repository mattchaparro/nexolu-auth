"""Modelos de persistencia del servicio.

Este servicio se queda con QUIEN ERES. Deliberadamente NO hay roles ni
permisos aca: los de caja viven en nexolu-pos-api y los de agenda en
nexolu-spa-api, cada uno con su `spatie/laravel-permission`. Centralizar
tambien la autorizacion volveria esto el cuello de botella de todo el
ecosistema (ver README.md, seccion "Alcance").
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from nexolu_auth.core.db.session import Base


def _uuid() -> str:
    return uuid.uuid4().hex


class Identity(Base):
    """La persona. En la Fase 1 hay exactamente una fila: el superadmin.

    `email` se guarda siempre en minusculas (ver core/identities.py) porque
    es la llave natural con la que los consumidores hacen el fallback, y una
    comparacion sensible a mayusculas ahi seria un 403 silencioso.
    """

    __tablename__ = "identities"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(191), unique=True)
    full_name: Mapped[str] = mapped_column(String(128), default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    credentials: Mapped[list[Credential]] = relationship(back_populates="identity")
    linked_accounts: Mapped[list[LinkedAccount]] = relationship(back_populates="identity")


class Credential(Base):
    """Un metodo de acceso por fila. En la Fase 1 solo existe `password`.

    Tabla aparte de `identities` a proposito: agregar TOTP en la Fase 2 es
    insertar una fila con `type='totp'`, no una migracion sobre la tabla
    central de identidad.

    `secret` NO se cifra con Fernet. Un hash bcrypt es irreversible por
    definicion; envolverlo en `EncryptedString` solo agregaria un modo de
    falla (perder la master key = perder el login) sin ganar nada. El dia
    que entre TOTP, ESE secreto si es reversible y ahi si aplica el patron
    de `core/security/crypto.py` de los otros servicios.
    """

    __tablename__ = "credentials"
    __table_args__ = (UniqueConstraint("identity_id", "type", name="uq_credential_identity_type"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    identity_id: Mapped[str] = mapped_column(ForeignKey("identities.id"), index=True)
    type: Mapped[str] = mapped_column(String(32))  # password (fase 2: totp)
    secret: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    identity: Mapped[Identity] = relationship(back_populates="credentials")


class LinkedAccount(Base):
    """El mapeo explicito de una identidad a su fila de `users` en un producto.

    Por que un mapeo y no cruzar por email: `UpdateProfileRequest` de
    nexolu-pos-api permite a cualquier usuario autenticado cambiar su propio
    correo (`PUT /api/v1/me`). Con vinculo por email, editar tu perfil en el
    POS te desconectaria del SSO en silencio. Ademas cada producto tiene su
    propia base: hoy los correos coinciden porque los escribio la misma
    persona, nada en el esquema lo garantiza.

    `external_user_id` es String porque los ids de los productos son enteros
    hoy pero el contrato del claim `account` es opaco - el consumidor sabe
    como interpretarlo, este servicio no.
    """

    __tablename__ = "linked_accounts"
    __table_args__ = (
        UniqueConstraint("identity_id", "product", name="uq_linked_account_identity_product"),
        UniqueConstraint("product", "external_user_id", name="uq_linked_account_product_user"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    identity_id: Mapped[str] = mapped_column(ForeignKey("identities.id"), index=True)
    product: Mapped[str] = mapped_column(String(64))
    external_user_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    external_email: Mapped[str | None] = mapped_column(String(191), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    identity: Mapped[Identity] = relationship(back_populates="linked_accounts")


class AuthSession(Base):
    """La sesion SSO del navegador en auth.nexolu.co.

    Esto es lo que hace que el segundo producto no vuelva a pedir la
    contrasena: la cookie apunta aca, y mientras la fila viva, pedir una
    asercion para otro producto es un 302 sin formulario.

    Se guarda `token_hash` (SHA-256) y nunca el token: si alguien lee esta
    tabla no puede hacerse pasar por la sesion. Mismo criterio que
    `api_key_hash` en los otros servicios.
    """

    __tablename__ = "auth_sessions"
    __table_args__ = (Index("ix_auth_sessions_identity", "identity_id"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    identity_id: Mapped[str] = mapped_column(ForeignKey("identities.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class LoginAttempt(Base):
    """Rate limiting y auditoria, sin dependencias nuevas.

    Hoy no hay throttle en NINGUN login del ecosistema (ni
    `pos-api/routes/api.php:213` ni el del panel). Como este servicio pasa a
    ser la puerta unica de una identidad que abre cuatro sistemas, el limite
    deja de ser opcional. Contar filas sale gratis y de paso queda el rastro
    de quien intento entrar.
    """

    __tablename__ = "login_attempts"
    __table_args__ = (
        Index("ix_login_attempts_ip", "ip", "created_at"),
        Index("ix_login_attempts_email", "email", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(191))
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    succeeded: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
