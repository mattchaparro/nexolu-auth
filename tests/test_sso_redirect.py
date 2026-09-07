from __future__ import annotations

from urllib.parse import urlparse

from tests.conftest import TEST_EMAIL, TEST_PASSWORD


def test_producto_desconocido_no_redirige_a_ningun_lado(client):
    """400 con pagina de error y SIN header Location.

    Si esto redirigiera seria, precisamente, el open redirect que el diseno
    elimina al no aceptar `redirect_uri` del query string.
    """
    response = client.get("/login?product=https://evil.example.com", follow_redirects=False)

    assert response.status_code == 400
    assert "location" not in response.headers


def test_sin_product_tampoco_redirige(client):
    response = client.get("/login", follow_redirects=False)

    assert response.status_code == 400
    assert "location" not in response.headers


def test_sin_sesion_muestra_el_formulario(client, identity):
    response = client.get("/login?product=nexolu-admin", follow_redirects=False)

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert 'name="password"' in response.text


def test_login_por_formulario_redirige_con_el_fragmento(client, identity):
    response = client.post(
        "/login",
        data={"product": "nexolu-admin", "email": TEST_EMAIL, "password": TEST_PASSWORD},
        follow_redirects=False,
    )

    assert response.status_code == 302

    location = response.headers["location"]
    assert location.startswith("https://admin.nexolu.test/iniciar-sesion#")


def test_el_parametro_del_fragmento_se_llama_auth_token(client, identity):
    """Regresion de la colision mas probable de todo el proyecto.

    `stashSsoTokenFromUrl()` corre hoy, vivo, en nexolu-pos-front/src/main.ts
    sirviendo al SSO del monolito legacy, que emite `#token=`. Si este
    servicio usara ese mismo nombre, ese helper se comeria la asercion, la
    guardaria como si fuera un PAT de Sanctum, y TODAS las peticiones darian
    401 sin causa visible.
    """
    response = client.post(
        "/login",
        data={"product": "nexolu-pos-api", "email": TEST_EMAIL, "password": TEST_PASSWORD},
        follow_redirects=False,
    )

    fragmento = urlparse(response.headers["location"]).fragment

    assert fragmento.startswith("auth_token=")
    assert not fragmento.startswith("token=")


def test_el_redirect_no_se_cachea_ni_filtra_por_referer(client, identity):
    response = client.post(
        "/login",
        data={"product": "nexolu-admin", "email": TEST_EMAIL, "password": TEST_PASSWORD},
        follow_redirects=False,
    )

    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"


def test_con_sesion_viva_no_vuelve_a_pedir_la_contrasena(client, identity):
    """ESTO es el SSO: el segundo producto es un 302 sin formulario."""
    primero = client.post(
        "/login",
        data={"product": "nexolu-admin", "email": TEST_EMAIL, "password": TEST_PASSWORD},
        follow_redirects=False,
    )
    assert primero.status_code == 302

    segundo = client.get("/login?product=nexolu-pos-api", follow_redirects=False)

    assert segundo.status_code == 302
    assert segundo.headers["location"].startswith("https://pos.nexolu.test/iniciar-sesion#")


def test_credenciales_malas_reenvian_el_formulario_con_error(client, identity):
    response = client.post(
        "/login",
        data={"product": "nexolu-admin", "email": TEST_EMAIL, "password": "equivocada"},
        follow_redirects=False,
    )

    assert response.status_code == 401
    assert "location" not in response.headers
    assert "Correo o contrasena incorrectos." in response.text


def test_el_destino_no_se_puede_forzar_desde_el_query(client, identity):
    """`redirect_uri` simplemente no se lee: el destino sale de la config
    del servicio, siempre."""
    response = client.post(
        "/login?redirect_uri=https://evil.example.com",
        data={"product": "nexolu-admin", "email": TEST_EMAIL, "password": TEST_PASSWORD},
        follow_redirects=False,
    )

    assert response.headers["location"].startswith("https://admin.nexolu.test/")
