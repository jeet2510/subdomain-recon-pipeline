import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


os.environ["DATA_DIR"] = "/tmp/recon-dash-test-data"
import app as recon_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    test_engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}", connect_args={"check_same_thread": False})
    test_session = sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr(recon_app, "engine", test_engine)
    monkeypatch.setattr(recon_app, "SessionLocal", test_session)
    recon_app.Base.metadata.create_all(test_engine)
    with TestClient(recon_app.app) as test_client:
        yield test_client
    recon_app.Base.metadata.drop_all(test_engine)
    test_engine.dispose()


def test_domain_validation_rejects_internal_and_malformed_names():
    assert recon_app.validate_domain("Example.COM") == "example.com"
    for domain in ("localhost", "printer.internal", "bad domain", "-bad.example.com"):
        with pytest.raises(ValueError):
            recon_app.validate_domain(domain)


def test_scope_filter_and_merge_normalize_names():
    merged = recon_app.merge_subdomains([
        {"name": "*.WWW.Example.com", "sources": ["crt.sh"]},
        {"name": "www.example.com", "sources": ["subfinder"]},
        {"name": "example.com.evil.test", "sources": ["out-of-scope"]},
    ], "example.com")
    assert merged == [{"name": "www.example.com", "sources": ["crt.sh", "subfinder"]}]


def test_import_persists_only_in_scope_rows_and_diff(client, tmp_path, monkeypatch):
    monkeypatch.setattr(recon_app, "DATA_DIR", tmp_path / "data")
    first = client.post("/api/import", data={"domain": "example.com"}, files={"file": (
        "results.json", b'{"subdomains":["a.example.com","outside.test"],"live_hosts":[]}', "application/json")})
    assert first.status_code == 201
    second = client.post("/api/import", data={"domain": "example.com"}, files={"file": (
        "results.json", b'{"subdomains":["a.example.com","b.example.com"],"live_hosts":['
        b'{"url":"https://www.example.com","host":"www.example.com","status_code":200},'
        b'{"url":"https://outside.test","host":"outside.test","status_code":200},'
        b'{"url":"https://api.example.com","host":"www.example.com","status_code":200}]}', "application/json")})
    assert second.status_code == 201
    assert second.json()["live_hosts"] == 1
    diff = client.get(f"/api/scans/{second.json()['id']}/diff", params={"compare_to": first.json()["id"]})
    assert diff.json() == {"new": ["b.example.com"], "removed": [], "unchanged": ["a.example.com"]}
    details = client.get(f"/api/scans/{second.json()['id']}").json()
    first_seen = {row["name"]: row["first_seen_scan_id"] for row in details["subdomains"]}
    assert first_seen == {"a.example.com": first.json()["id"], "b.example.com": second.json()["id"]}
    assert details["live_hosts"] == [{"url": "https://www.example.com", "host": "www.example.com",
                                     "status_code": 200, "title": None}]
    assert client.get(f"/api/scans/{second.json()['id']}/export?format=csv").status_code == 200
    report = client.get(f"/api/scans/{second.json()['id']}/report")
    assert "did not contact the domain" in report.text
    assert (tmp_path / "data" / "example.com" / first.json()["id"] / "summary.json").exists()


def test_import_accepts_csv_and_rejects_bad_domain(client):
    response = client.post("/api/import", data={"domain": "example.com"}, files={"file": (
        "results.csv", b"name,sources\na.example.com,assetfinder", "text/csv")})
    assert response.status_code == 201
    rejected = client.post("/api/import", data={"domain": "localhost"}, files={"file": (
        "results.csv", b"name\na.localhost", "text/csv")})
    assert rejected.status_code == 400


def test_api_requires_bearer_token_when_configured(client, monkeypatch):
    monkeypatch.setattr(recon_app, "APP_TOKEN", "test-token")
    assert client.get("/api/domains").status_code == 401
    assert client.get("/api/domains", headers={"Authorization": "Bearer test-token"}).status_code == 200