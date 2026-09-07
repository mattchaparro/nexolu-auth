"""Siembra la identidad del superadmin y la vincula a cada producto.

    docker compose run --rm auth python -m scripts.seed_identity \\
      --email mattchaparrof@gmail.com --name "Matt Chaparro" \\
      --link nexolu-pos-api=1 --link nexolu-admin=1

La contrasena se toma copiando el hash bcrypt que ya existe en
`pos_saas.users#1`, para seguir usando la misma de siempre:

    mysql -N -e "SELECT password FROM pos_saas.users WHERE id = 1" | \\
      docker compose run --rm -T auth python -m scripts.seed_identity ... --password-hash -

`--password-hash -` lee de stdin a proposito: pasar un hash por argv lo deja
en el historial del shell y en `ps`. Si no se pasa hash, el script pide una
contrasena nueva por getpass y la hashea.

El hash de Laravel viene con prefijo `$2y$` y se acepta tal cual, sin
conversion (ver core/security/passwords.py).

Es idempotente: correrlo dos veces actualiza en vez de duplicar.
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
from datetime import datetime

from sqlalchemy import select

from nexolu_auth.core.db.entities import Credential, Identity, LinkedAccount
from nexolu_auth.core.db.session import get_sessionmaker, init_models
from nexolu_auth.core.identities import PASSWORD, normalize_email
from nexolu_auth.core.security.passwords import hash_password


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Siembra la identidad del superadmin.")
    parser.add_argument("--email", required=True)
    parser.add_argument("--name", default="")
    parser.add_argument(
        "--password-hash",
        help="Hash bcrypt existente ($2y$ de Laravel sirve). '-' lee de stdin.",
    )
    parser.add_argument(
        "--link",
        action="append",
        default=[],
        metavar="PRODUCTO=ID",
        help="Vinculo a un producto, repetible. Ej: --link nexolu-pos-api=1",
    )
    return parser.parse_args()


def resolve_password_hash(raw: str | None) -> str:
    if raw == "-":
        value = sys.stdin.read().strip()
        if not value:
            raise SystemExit("No llego ningun hash por stdin.")
        return value

    if raw:
        return raw

    first = getpass.getpass("Contrasena nueva: ")
    second = getpass.getpass("Confirmala: ")

    if first != second:
        raise SystemExit("Las contrasenas no coinciden.")
    if len(first) < 12:
        raise SystemExit("Usa al menos 12 caracteres.")

    return hash_password(first)


def parse_links(values: list[str]) -> dict[str, str]:
    links: dict[str, str] = {}

    for value in values:
        if "=" not in value:
            raise SystemExit(f"--link mal formado: {value!r}. Se espera PRODUCTO=ID.")
        product, external_id = value.split("=", 1)
        links[product.strip()] = external_id.strip()

    return links


async def seed(email: str, full_name: str, password_hash: str, links: dict[str, str]) -> None:
    # En SQLite de desarrollo las tablas se crean solas; en MySQL el
    # esquema ya lo dejo `alembic upgrade head` en el deploy.
    await init_models()

    async with get_sessionmaker()() as session:
        normalized = normalize_email(email)

        result = await session.execute(select(Identity).where(Identity.email == normalized))
        identity = result.scalar_one_or_none()

        if identity is None:
            identity = Identity(email=normalized, full_name=full_name, is_active=True)
            session.add(identity)
            await session.flush()
            print(f"[+] Identidad creada: {normalized} ({identity.id})")
        else:
            identity.full_name = full_name or identity.full_name
            identity.is_active = True
            print(f"[=] Identidad ya existia: {normalized} ({identity.id})")

        result = await session.execute(
            select(Credential).where(
                Credential.identity_id == identity.id, Credential.type == PASSWORD
            )
        )
        credential = result.scalar_one_or_none()

        if credential is None:
            session.add(
                Credential(
                    identity_id=identity.id,
                    type=PASSWORD,
                    secret=password_hash,
                    is_active=True,
                    password_changed_at=datetime.utcnow(),
                )
            )
            print("[+] Credencial de contrasena creada")
        else:
            credential.secret = password_hash
            credential.is_active = True
            credential.password_changed_at = datetime.utcnow()
            print("[=] Credencial de contrasena actualizada")

        for product, external_id in links.items():
            result = await session.execute(
                select(LinkedAccount).where(
                    LinkedAccount.identity_id == identity.id,
                    LinkedAccount.product == product,
                )
            )
            linked = result.scalar_one_or_none()

            if linked is None:
                session.add(
                    LinkedAccount(
                        identity_id=identity.id,
                        product=product,
                        external_user_id=external_id,
                        external_email=normalized,
                        is_active=True,
                    )
                )
                print(f"[+] Vinculo {product} -> users#{external_id}")
            else:
                linked.external_user_id = external_id
                linked.external_email = normalized
                linked.is_active = True
                print(f"[=] Vinculo {product} -> users#{external_id} (actualizado)")

        await session.commit()

        print()
        print("Listo. Si quieres que el break-glass del panel comparta esta misma")
        print("contrasena, pega este hash en ADMIN_PASSWORD_HASH del .env de")
        print("nexolu-admin (es una eleccion explicita, no pasa solo):")
        print()
        print(f"ADMIN_PASSWORD_HASH={password_hash}")
        print()
        print("Y verifica que ADMIN_EMAIL sea exactamente este correo: un desfase")
        print("ahi da 403 silencioso en el SSO mientras el break-glass sigue vivo.")
        print(f"ADMIN_EMAIL={normalized}")


def main() -> None:
    args = parse_args()
    asyncio.run(
        seed(args.email, args.name, resolve_password_hash(args.password_hash), parse_links(args.link))
    )


if __name__ == "__main__":
    main()
