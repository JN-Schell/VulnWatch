import json

import pytest

from app.models import RiskPolicy
from app.risk import calculate_risk, severity
from app.schemas import PolicyInput


def test_risk_and_cvss_interpretation():
    policy = RiskPolicy(low=0.1, medium=4, high=7, critical=9, unknown_baseline=5, internet_multiplier=1.25)
    assert calculate_risk(10, 5, "internet", policy) == 100
    assert calculate_risk(7, 1, "internal", policy) == 47.6
    assert calculate_risk(None, 5, "internal", policy) == 50
    assert calculate_risk(0, 5, "internet", policy) == 0
    for score, level in [
        (None, "unknown"),
        (0, "none"),
        (0.1, "low"),
        (4, "medium"),
        (7, "high"),
        (9, "critical"),
    ]:
        assert severity(score, policy) == level
    with pytest.raises(ValueError):
        PolicyInput(high=9.5, critical=8)


def test_remediation_and_reopening(imported):
    client, payload = imported
    finding = client.get("/api/findings").json()["items"][0]
    identifier = finding["id"]

    def update(**changes):
        nonlocal finding
        response = client.patch(
            f"/api/findings/{identifier}",
            json={
                "revision": finding["revision"],
                "note": "Patched and verified against package inventory",
                **changes,
            },
        )
        if response.status_code == 200:
            finding = response.json()
        return response

    assert update(status="verified", kind="verification").status_code == 409
    assert update(status="in_progress", assignee_id=1, due_at="2026-01-01T00:00:00Z").status_code == 200
    assert finding["overdue"]
    assert update(status="mitigated").status_code == 422
    assert update(status="mitigated", kind="mitigation").status_code == 200
    assert update(status="verified", kind="verification").status_code == 200
    assert finding["remediated_at"]
    assert client.get("/api/dashboard").json()["active"] == 0
    assert (
        client.patch(f"/api/findings/{identifier}", json={"revision": 1, "note": "Stale update"}).status_code
        == 409
    )
    assert (
        client.post(
            "/api/imports?adapter=generic-json", files={"file": ("again.json", json.dumps(payload))}
        ).status_code
        == 201
    )
    reopened = client.get(f"/api/findings/{identifier}").json()
    assert reopened["status"] == "open"
    assert reopened["remediated_at"] is None
    assert len(reopened["history"]) == 5


def test_permissions_acceptance_assignment_and_policy(imported, authenticated):
    client, _ = imported
    finding = client.get("/api/findings").json()["items"][0]
    authenticated("analyst")
    assert (
        client.patch(
            f"/api/findings/{finding['id']}",
            json={"revision": finding["revision"], "status": "accepted", "note": "Accept"},
        ).status_code
        == 403
    )
    assert client.put("/api/policy", json=PolicyInput().model_dump()).status_code == 403
    assert (
        client.patch(
            f"/api/findings/{finding['id']}",
            json={"revision": finding["revision"], "assignee_id": 3, "note": "Assign viewer"},
        ).status_code
        == 422
    )
    authenticated("admin")
    old_history = len(client.get(f"/api/findings/{finding['id']}").json()["risk_history"])
    assert client.put("/api/policy", json=PolicyInput(critical=9.5).model_dump()).status_code == 200
    assert len(client.get(f"/api/findings/{finding['id']}").json()["risk_history"]) == old_history + 1
    report = client.get(f"/api/assets/{finding['asset']['id']}/report").json()
    assert report["total"] == 1
    assert client.get("/api/audit").status_code == 200
