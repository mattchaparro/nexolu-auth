"""Verificacion de contrasenas contra hashes bcrypt.

El hash puede venir de Laravel: `Hash::make()` emite el prefijo `$2y$` y
este modulo lo acepta tal cual, sin conversion (verificado con bcrypt 5.0,
ver tests/test_login.py::test_acepta_hash_2y_de_laravel). Eso es lo que
permite sembrar la identidad copiando el hash de `pos_saas.users#1` en vez
de fijar una contrasena nueva.
"""
from __future__ import annotations

import bcrypt

# Mismo costo que usa Laravel por defecto.
_ROUNDS = 12


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=_ROUNDS)).decode()


def verify_password(password: str, password_hash: str) -> bool:
    """Falla cerrado ante cualquier hash invalido o vacio.

    Mismo criterio que `verify_password` en nexolu-admin: un hash corrupto o
    ausente NO puede resultar en un login exitoso, y tampoco debe reventar
    con un 500 que distinga ese caso de una contrasena equivocada.
    """
    if not password_hash:
        return False

    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except (ValueError, TypeError):
        return False
