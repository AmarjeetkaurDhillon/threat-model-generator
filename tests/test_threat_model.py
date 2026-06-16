import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import app, generate_threat_model
import pytest


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_index_page_loads(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Threat Model Generator" in response.data


def test_generate_with_web_app(client):
    response = client.post("/generate", data={
        "system_name": "Test System",
        "components": ["web_app"],
        "data_sensitivity": "medium"
    })
    assert response.status_code == 200
    assert b"Test System" in response.data
    assert b"STRIDE" in response.data or b"Spoofing" in response.data


def test_generate_with_multiple_components(client):
    response = client.post("/generate", data={
        "system_name": "Banking App",
        "components": ["web_app", "api", "database", "auth"],
        "data_sensitivity": "high"
    })
    assert response.status_code == 200
    assert b"Banking App" in response.data
    assert b"CRITICAL" in response.data


def test_generate_no_components_shows_error(client):
    response = client.post("/generate", data={
        "system_name": "Test System",
        "data_sensitivity": "medium"
    })
    assert response.status_code == 200
    assert b"Please select at least one component" in response.data


def test_threat_model_logic_web_app():
    threats, summary = generate_threat_model("Test", ["web_app"], "medium")
    assert len(threats) > 0
    assert "CRITICAL" in summary or "HIGH" in summary


def test_threat_model_high_sensitivity_upgrades_risk():
    threats_medium, _ = generate_threat_model("Test", ["api"], "medium")
    threats_high, _ = generate_threat_model("Test", ["api"], "high")
    medium_highs = len([t for t in threats_medium if t["risk"] == "HIGH"])
    high_highs = len([t for t in threats_high if t["risk"] == "HIGH"])
    assert high_highs >= medium_highs


def test_threats_sorted_by_severity():
    threats, _ = generate_threat_model("Test", ["web_app", "database"], "high")
    risk_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    scores = [risk_order[t["risk"]] for t in threats]
    assert scores == sorted(scores, reverse=True)