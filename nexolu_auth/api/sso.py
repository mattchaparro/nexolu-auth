"""La pantalla de login y el redirect de vuelta al producto.

HTML renderizado del lado del servidor, no un cuarto frontend: un repo Vue
traeria su build, su vhost y su pipeline para una sola pantalla. Ademas
evita el parpadeo de JS antes del redirect y no introduce NINGUNA superficie
CORS - el navegador *navega* aca, nunca le hace fetch.

Sobre el open redirect: `redirect_uri` no se acepta del query string. El
query lleva solo `product` y el destino sale de la config de este servicio.
Asi un open redirect no es algo contra lo que haya que defenderse con un
`startsWith`, es estructuralmente imposible. Lo que se pierde (volver al
deep link exacto) se recupera del lado correcto: cada front guarda la ruta
pretendida en su propio sessionStorage antes de rebotar, y ese destino nunca
sale de su origen.
"""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from nexolu_auth.config import Product, get_settings
from nexolu_auth.core import identities
from nexolu_auth.core.auth import rate_limit, sessions
from nexolu_auth.core.db.entities import Identity
from nexolu_auth.core.db.session import get_session
from nexolu_auth.core.security.assertions import mint_assertion

router = APIRouter(tags=["sso"])
logger = logging.getLogger(__name__)

templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))

# Un solo mensaje para correo desconocido, contrasena equivocada e identidad
# desactivada. Distinguirlos le diria a un atacante que correos existen.
CREDENCIALES_INVALIDAS = "Correo o contrasena incorrectos."
DEMASIADOS_INTENTOS = "Demasiados intentos. Espera unos minutos y vuelve a intentar."

# El fragmento se llama auth_token y NO token a proposito.
# `stashSsoTokenFromUrl()` corre hoy, vivo, en nexolu-pos-front/src/main.ts
# sirviendo al SSO del monolito legacy, que emite `#token=`. Si este
# servicio emitiera el mismo nombre, ese helper se comeria la asercion, la
# escribiria como si fuera un PAT de Sanctum, y TODAS las peticiones darian
# 401 sin causa visible en ningun lado.
FRAGMENT_PARAM = "auth_token"


def client_ip(request: Request) -> str | None:
    """nginx corre en el host y hace proxy_pass a 127.0.0.1, asi que
    `request.client.host` seria siempre el proxy. El vhost manda
    X-Forwarded-For (ver nexolu-infra/nginx/auth.nexolu.co.conf)."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:45]

    return request.client.host[:45] if request.client else None


def resolve_product(slug: str | None) -> Product | None:
    if not slug:
        return None

    return get_settings().products.get(slug)


def _no_store(response: Response) -> Response:
    """La respuesta que lleva la asercion no se cachea ni filtra por Referer."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def _producto_desconocido(request: Request, slug: str | None) -> HTMLResponse:
    """400 con pagina de error y SIN header Location.

    Si esto redirigiera a algun lado seria, precisamente, el open redirect
    que el diseno elimina.
    """
    logger.warning("sso.producto_desconocido", extra={"product": slug})

    return templates.TemplateResponse(
        request=request,
        name="error.html",
        context={
            "titulo": "Aplicacion desconocida",
            "detalle": "El enlace que seguiste no corresponde a ninguna aplicacion de Nexolu.",
        },
        status_code=400,
    )


async def _emitir_y_redirigir(
    session: AsyncSession, identity: Identity, slug: str, product: Product
) -> RedirectResponse:
    linked = await identities.get_linked_account(session, identity.id, slug)
    assertion = mint_assertion(
        identity,
        product,
        external_user_id=linked.external_user_id if linked else None,
    )

    logger.info(
        "sso.asercion_emitida",
        extra={
            "identity_id": identity.id,
            "product": slug,
            "audience": product.audience,
            "vinculo": "linked_account" if linked else "sin_vinculo",
        },
    )

    response = RedirectResponse(
        url=f"{product.redirect_url}#{FRAGMENT_PARAM}={assertion}",
        status_code=302,
    )
    return _no_store(response)


@router.get("/login")
async def login_form(
    request: Request,
    product: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> Response:
    resolved = resolve_product(product)
    if resolved is None:
        return _producto_desconocido(request, product)

    # Con sesion viva no se vuelve a pedir la contrasena: ESTO es el SSO.
    identity = await sessions.resolve_session(session, request.cookies.get(sessions.COOKIE_NAME))
    if identity is not None:
        return await _emitir_y_redirigir(session, identity, product, resolved)

    return _no_store(
        templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"product": product, "product_name": resolved.name, "error": None},
        )
    )


@router.post("/login")
async def login_submit(
    request: Request,
    product: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    session: AsyncSession = Depends(get_session),
) -> Response:
    resolved = resolve_product(product)
    if resolved is None:
        return _producto_desconocido(request, product)

    normalized = identities.normalize_email(email)
    ip = client_ip(request)

    def _con_error(mensaje: str, status_code: int) -> Response:
        return _no_store(
            templates.TemplateResponse(
                request=request,
                name="login.html",
                context={
                    "product": product,
                    "product_name": resolved.name,
                    "error": mensaje,
                    "email": email,
                },
                status_code=status_code,
            )
        )

    if await rate_limit.is_rate_limited(session, normalized, ip):
        logger.warning("sso.login_bloqueado", extra={"email": normalized, "ip": ip})
        return _con_error(DEMASIADOS_INTENTOS, 429)

    identity = await identities.authenticate(session, normalized, password)

    await rate_limit.record_attempt(session, normalized, ip, succeeded=identity is not None)

    if identity is None:
        logger.info("sso.login_fallido", extra={"email": normalized, "ip": ip})
        return _con_error(CREDENCIALES_INVALIDAS, 401)

    token = await sessions.create_session(
        session, identity, user_agent=request.headers.get("user-agent"), ip=ip
    )

    logger.info("sso.login_exitoso", extra={"identity_id": identity.id, "product": product})

    response = await _emitir_y_redirigir(session, identity, product, resolved)
    response.set_cookie(sessions.COOKIE_NAME, token, **sessions.cookie_kwargs())

    return response


@router.get("/logout")
async def logout(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> Response:
    await sessions.revoke_session(session, request.cookies.get(sessions.COOKIE_NAME))

    response = templates.TemplateResponse(
        request=request,
        name="error.html",
        context={"titulo": "Sesion cerrada", "detalle": "Ya puedes cerrar esta pestana."},
    )
    response.delete_cookie(sessions.COOKIE_NAME, path="/")

    return _no_store(response)
