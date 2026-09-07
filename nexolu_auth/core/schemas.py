"""Contratos de entrada y salida de la API JSON."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class LoginRequest(BaseModel):
    # `str` y no `EmailStr` a proposito: en un endpoint de login, validar el
    # formato del correo produce un 422 donde deberia haber un 401, y esa
    # diferencia le dice a quien prueba si el string llego siquiera a
    # compararse. Un fallo de credenciales tiene que verse igual siempre.
    # El formulario ya usa type="email" para la ayuda del navegador.
    email: str
    password: str


class LinkedAccountOut(BaseModel):
    product: str
    external_user_id: str | None
    external_email: str | None
    is_active: bool


class IdentityOut(BaseModel):
    id: str
    email: str
    full_name: str
    is_active: bool
    linked_accounts: list[LinkedAccountOut] = []


class LoginResponse(BaseModel):
    identity: IdentityOut


class AuthorizeRequest(BaseModel):
    product: str


class AuthorizeResponse(BaseModel):
    assertion: str
    audience: str
    expires_in: int


class SessionOut(BaseModel):
    id: str
    user_agent: str | None
    ip: str | None
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime
