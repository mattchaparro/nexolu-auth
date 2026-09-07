"""Configuracion del servicio.

Las identidades y sus credenciales viven en la base de datos. Las variables
de entorno tienen solo lo que es del proceso: la llave privada de firma, el
catalogo de productos que pueden pedir una asercion, y los limites.
"""
from __future__ import annotations

import base64
import binascii
import json
from functools import lru_cache

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Product(BaseModel):
    """Un consumidor que puede pedir una asercion.

    `audience` es lo que va en el claim `aud`, y `redirect_url` es a donde
    vuelve el navegador con el fragmento. Ese destino NO se acepta del query
    string a proposito: es la unica forma de que un open redirect sea
    imposible en vez de algo contra lo que hay que defenderse (ver
    api/sso.py).
    """

    name: str
    audience: str
    redirect_url: str


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = Field(default="sqlite+aiosqlite:///./nexolu_auth.db")

    auth_issuer: str = "https://auth.nexolu.co"
    # PEM de la llave privada RSA, en base64 y en UNA linea. Un PEM crudo es
    # multilinea y se trunca al pegarlo en un .env sin que nadie lo note -
    # `scripts/generate_keypair.py` imprime el `KEY=value` exacto para pegar.
    auth_jwt_private_key: str = ""
    auth_jwt_kid: str = ""
    # 120 s: la asercion vive un instante en un fragmento de URL y se gasta
    # al cargar la pagina. El leeway de los verificadores cubre el reloj.
    auth_assertion_ttl_seconds: int = 120
    auth_session_ttl_hours: int = 12
    auth_products_json: str = "{}"

    auth_login_max_attempts: int = 5
    auth_login_window_minutes: int = 15

    # Se apaga solo en desarrollo local (http://localhost no acepta cookies
    # `Secure`). En produccion nunca.
    auth_cookie_secure: bool = True

    nexolu_platform_api_key: str = ""
    log_level: str = "INFO"

    @property
    def products(self) -> dict[str, Product]:
        raw = json.loads(self.auth_products_json or "{}")
        return {slug: Product(**data) for slug, data in raw.items()}

    @property
    def private_key_pem(self) -> bytes:
        """PEM crudo listo para `cryptography`.

        Falla cerrado y NOMBRANDO la variable: sin esto el servicio no puede
        emitir nada, y el modo de falla mas probable es un base64 mal pegado,
        no una ausencia. Mismo criterio que `_fernet()` en los otros cores.
        """
        if not self.auth_jwt_private_key:
            raise RuntimeError(
                "AUTH_JWT_PRIVATE_KEY esta vacia: el servicio no puede firmar aserciones. "
                "Generala con `python -m scripts.generate_keypair`."
            )

        try:
            return base64.b64decode(self.auth_jwt_private_key, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise RuntimeError(
                "AUTH_JWT_PRIVATE_KEY no es base64 valido. Tiene que ser el PEM completo "
                "codificado en base64 y en una sola linea (ver scripts/generate_keypair.py)."
            ) from exc


@lru_cache
def get_settings() -> Settings:
    return Settings()
