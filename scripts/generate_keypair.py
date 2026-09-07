"""Genera el par RSA de firma e imprime las lineas de .env listas para pegar.

Se corre UNA vez, fuera del repo:

    docker compose run --rm auth python -m scripts.generate_keypair

RSA-2048 y no 4096: la asercion viaja en un fragmento de URL y 4096 no
agrega nada al modelo de amenaza, solo largo.

Todo sale en base64 de una sola linea a proposito. Pegar un PEM multilinea
en un archivo .env es facilisimo de truncar sin notarlo, y el sintoma seria
que TODOS los canjes fallan a la vez sin un error que apunte a la causa.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def main() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    kid = hashlib.sha256(public_der).hexdigest()[:16]
    private_b64 = base64.b64encode(private_pem).decode()
    public_b64 = base64.b64encode(public_pem).decode()

    print("=" * 72)
    print("1) En el .env de nexolu-auth (SECRETO - nunca sale de este servicio):")
    print("=" * 72)
    print(f"AUTH_JWT_KID={kid}")
    print(f"AUTH_JWT_PRIVATE_KEY={private_b64}")
    print()
    print("=" * 72)
    print("2) En el .env de CADA consumidor (nexolu-admin, nexolu-pos-api,")
    print("   nexolu-spa-api). No es secreto, es la llave publica:")
    print("=" * 72)
    print(f'NEXOLU_AUTH_PUBLIC_KEYS={{"{kid}":"{public_b64}"}}')
    print()
    print("   Para ROTAR: deja la llave vieja en ese diccionario y agrega la")
    print("   nueva. Las dos conviven, asi que no hay ventana de downtime;")
    print("   recien cuando los 3 consumidores tengan ambas, cambia la llave")
    print("   de firma de este servicio.")
    print()
    print("=" * 72)
    print("3) Llave publica en PEM, por si hace falta inspeccionarla:")
    print("=" * 72)
    print(public_pem.decode())


if __name__ == "__main__":
    main()
