from fastapi.testclient import TestClient

from reconix_api.main import create_app
from tests.fakes import build_fake_interfaces


def test_the_startup_step_runs_once_before_requests():
    calls = []

    async def startup() -> None:
        calls.append("startup")

    app = create_app(build_fake_interfaces()[0], startup=startup)
    with TestClient(app, base_url="http://127.0.0.1/api/v1") as client:
        assert calls == ["startup"]
        assert client.get("/health").status_code == 200
    assert calls == ["startup"]


def test_an_app_without_a_startup_step_still_starts():
    app = create_app(build_fake_interfaces()[0])
    with TestClient(app, base_url="http://127.0.0.1/api/v1") as client:
        assert client.get("/health").status_code == 200
