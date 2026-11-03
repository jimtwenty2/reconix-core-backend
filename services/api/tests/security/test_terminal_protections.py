"""WS /terminal gets the same protections as every HTTP route, checked by hand because
WebSockets are not in openapi.json (test_api_protections reads its routes from there)."""

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from reconix_api.main import create_app
from tests.fakes import OPERATOR_TOKEN, build_fake_interfaces, fake_mask_secrets

GOOD = {"Origin": "http://127.0.0.1:3000", "Authorization": f"Bearer {OPERATOR_TOKEN}"}


@pytest.mark.parametrize(
    ("host", "headers", "code"),
    [
        ("127.0.0.1", {"Origin": GOOD["Origin"]}, 4401),  # no session token
        ("127.0.0.1", {"Authorization": GOOD["Authorization"]}, 4403),  # not from the web
        ("127.0.0.1", {**GOOD, "Origin": "http://attacker.example"}, 4403),
        ("attacker.example", GOOD, 4403),  # DNS rebinding
    ],
)
def test_terminal_refuses_before_starting_anything(host, headers, code):
    app = create_app(build_fake_interfaces()[0], mask_secrets=fake_mask_secrets)
    with pytest.raises(WebSocketDisconnect) as refused:
        with TestClient(app).websocket_connect(f"ws://{host}/api/v1/terminal", headers=headers):
            pass
    assert refused.value.code == code
