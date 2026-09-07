from __future__ import annotations


def test_health(client):
    """En /health y no en /v1/health: el vhost de nginx y deploy.sh dependen
    de esa ruta exacta. Cambiarla rompe la verificacion del despliegue."""
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_openapi(client):
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200
