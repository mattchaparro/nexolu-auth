"""La misma funcionalidad del formulario, en JSON.

Existe para tests, para curl y para cualquier cliente que no sea un
navegador. El camino que usan las personas es el de api/sso.py; este no
duplica logica, llama a los mismos modulos de core/.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from nexolu_auth.api.sso import (
    CREDENCIALES_INVALIDAS,
    DEMASIADOS_INTENTOS,
    client_ip,
    resolve_product,
)
from nexolu_auth.config import get_settings
from nexolu_auth.core import identities
from nexolu_auth.core.auth import rate_limit, sessions
from nexolu_auth.core.auth.dependencies import get_current_identity
from nexolu_auth.core.db.entities import Identity
from nexolu_auth.core.db.session import get_session
from nexolu_auth.core.schemas import (
    AuthorizeRequest,
    AuthorizeResponse,
    IdentityOut,
    LinkedAccountOut,
    LoginRequest,
    LoginResponse,
    SessionOut,
)
from nexolu_auth.core.security.assertions import mint_assertion

router = APIRouter(prefix="/v1/auth", tags=["auth"])


async def _identity_out(session: AsyncSession, identity: Identity) -> IdentityOut:
    linked = await identities.list_linked_accounts(session, identity.id)

    return IdentityOut(
        id=identity.id,
        email=identity.email,
        full_name=identity.full_name,
        is_active=identity.is_active,
        linked_accounts=[
            LinkedAccountOut(
                product=account.product,
                external_user_id=account.external_user_id,
                external_email=account.external_email,
                is_active=account.is_active,
            )
            for account in linked
        ],
    )


@router.post("/login", response_model=LoginResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_session),
) -> LoginResponse:
    normalized = identities.normalize_email(payload.email)
    ip = client_ip(request)

    if await rate_limit.is_rate_limited(session, normalized, ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=DEMASIADOS_INTENTOS
        )

    identity = await identities.authenticate(session, normalized, payload.password)
    await rate_limit.record_attempt(session, normalized, ip, succeeded=identity is not None)

    if identity is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=CREDENCIALES_INVALIDAS
        )

    token = await sessions.create_session(
        session, identity, user_agent=request.headers.get("user-agent"), ip=ip
    )
    response.set_cookie(sessions.COOKIE_NAME, token, **sessions.cookie_kwargs())

    return LoginResponse(identity=await _identity_out(session, identity))


@router.post("/authorize", response_model=AuthorizeResponse)
async def authorize(
    payload: AuthorizeRequest,
    identity: Identity = Depends(get_current_identity),
    session: AsyncSession = Depends(get_session),
) -> AuthorizeResponse:
    product = resolve_product(payload.product)

    if product is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Aplicacion desconocida."
        )

    linked = await identities.get_linked_account(session, identity.id, payload.product)
    assertion = mint_assertion(
        identity, product, external_user_id=linked.external_user_id if linked else None
    )

    return AuthorizeResponse(
        assertion=assertion,
        audience=product.audience,
        expires_in=get_settings().auth_assertion_ttl_seconds,
    )


@router.get("/me", response_model=IdentityOut)
async def me(
    identity: Identity = Depends(get_current_identity),
    session: AsyncSession = Depends(get_session),
) -> IdentityOut:
    return await _identity_out(session, identity)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_session),
) -> None:
    await sessions.revoke_session(session, request.cookies.get(sessions.COOKIE_NAME))
    response.delete_cookie(sessions.COOKIE_NAME, path="/")


@router.get("/sessions", response_model=list[SessionOut])
async def active_sessions(
    identity: Identity = Depends(get_current_identity),
    session: AsyncSession = Depends(get_session),
) -> list[SessionOut]:
    return [
        SessionOut(
            id=item.id,
            user_agent=item.user_agent,
            ip=item.ip,
            created_at=item.created_at,
            last_used_at=item.last_used_at,
            expires_at=item.expires_at,
        )
        for item in await sessions.list_active(session, identity.id)
    ]
