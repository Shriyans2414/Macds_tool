from fastapi.testclient import TestClient
from control_plane.api.main import app

client = TestClient(app)

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200

def test_logs_no_key():
    resp = client.post("/api/logs", json={"timestamp": 0, "attack_type": "none", "source_ip": "1.1.1.1"})
    assert resp.status_code == 401

def test_logs_with_key():
    resp = client.post("/api/logs", json={
        "timestamp": 0, "attack_type": "none", "source_ip": "1.1.1.1"
    }, headers={"X-MACDS-Key": "test-key"})
    assert resp.status_code == 200

def test_get_verdicts():
    resp = client.get("/api/verdicts", headers={"X-MACDS-Key": "test-key"})
    assert resp.status_code == 200
    assert "verdicts" in resp.json()

def test_get_action():
    resp = client.get("/api/action", headers={"X-MACDS-Key": "test-key"})
    assert resp.status_code == 200
    assert "action" in resp.json()
