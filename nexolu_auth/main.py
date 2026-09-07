"""Punto de entrada del servicio: `uvicorn nexolu_auth.main:app`."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from nexolu_auth.api import jwks, sso
from nexolu_auth.api.v1 import auth, health
from nexolu_auth.config import get_settings
from nexolu_auth.core.db.session import init_models
from nexolu_auth.core.telemetry.logging import configure_logging


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level)

    # Autocrear tablas solo tiene sentido en SQLite de desarrollo. En
    # produccion (MySQL) el esquema se maneja con `alembic upgrade head`,
    # corrido como parte del despliegue, no al arrancar el proceso.
    if settings.database_url.startswith("sqlite"):
        await init_models()

    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="Nexolu Auth",
        description=(
            "Identidad centralizada del ecosistema Nexolu. Emite aserciones SSO de vida "
            "corta que cada producto verifica localmente y canjea por su credencial nativa."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )

    # Sin CORSMiddleware a proposito: el navegador NAVEGA a este servicio
    # (formulario + redirect), nunca le hace fetch desde otro origen. La
    # unica API JSON que se consume cross-origin es la de cada consumidor,
    # no esta.
    app.include_router(health.router)
    app.include_router(jwks.router)
    app.include_router(sso.router)
    app.include_router(auth.router)

    return app


app = create_app()
