import pytest
from fastapi.testclient import TestClient

from reconix_api.main import create_app
from tests.fakes import OPERATOR_TOKEN, VIEWER_TOKEN, build_fake_interfaces, fake_mask_secrets


@pytest.fixture
def fakes():
    interfaces, parts = build_fake_interfaces()
    return interfaces, parts


@pytest.fixture
def app(fakes):
    interfaces, _ = fakes
    return create_app(interfaces, mask_secrets=fake_mask_secrets)


@pytest.fixture
def client(app):
    # The Host check only accepts this computer, so tests call 127.0.0.1, not "testserver".
    return TestClient(app, base_url="http://127.0.0.1/api/v1")


@pytest.fixture
def operator_headers():
    return {"Authorization": f"Bearer {OPERATOR_TOKEN}"}


@pytest.fixture
def viewer_headers():
    return {"Authorization": f"Bearer {VIEWER_TOKEN}"}
