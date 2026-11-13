import json

import pytest
from sqlalchemy import func, select

from app.adapters import ImportError, parse_import
from app.models import Finding, ImportJob, Vulnerability


def test_duplicate_detection_cross_scanner_and_history(imported, database):
    client, payload = imported
    payload["findings"][0]["source"] = "another-scanner"
    response = client.post(
        "/api/imports?adapter=generic-json", files={"file": ("scan.json", json.dumps(payload))}
    )
    assert response.json()["created"] == 0
    assert response.json()["duplicates"] == 1
    finding = client.get("/api/findings").json()["items"][0]
    assert finding["occurrences"] == 2
    assert len(client.get(f"/api/findings/{finding['id']}").json()["history"]) == 1
    with database() as db:
        assert db.scalar(select(func.count(Finding.id))) == 1
        assert db.scalar(select(func.count(Vulnerability.id))) == 1


def test_batch_is_atomic(imported, database):
    client, payload = imported
    payload["findings"] += [
        {"asset": "server-01", "external_id": "scanner:new", "title": "New finding"},
        {"asset": "missing-asset", "external_id": "scanner:missing", "title": "Missing"},
    ]
    assert (
        client.post(
            "/api/imports?adapter=generic-json", files={"file": ("scan.json", json.dumps(payload))}
        ).status_code
        == 422
    )
    with database() as db:
        assert db.scalar(select(func.count(Finding.id))) == 1
        assert db.scalar(select(func.count(Vulnerability.id))) == 1
        assert db.scalar(select(ImportJob).where(ImportJob.status == "failed"))
        assert db.scalar(select(Finding)).occurrences == 1


@pytest.mark.parametrize(
    "content,filename,adapter",
    [
        (b"<script>alert(1)</script>", "scan.json", "generic-json"),
        (b'{"schema_version":"1.0","findings":[],"findings":[]}', "scan.json", "generic-json"),
        (b'{"schema_version":"1.0","findings":[]}', "scan.exe", "generic-json"),
        (b"\xff\xfe\x00", "scan.csv", "generic-csv"),
        (b"asset,title,title\nserver,x,x", "scan.csv", "generic-csv"),
        (b"asset,title,external_id\nserver,x,scanner:x,extra", "scan.csv", "generic-csv"),
        (b"asset,title,command\nserver,x,rm -rf /", "scan.csv", "generic-csv"),
        (
            b'{"schema_version":"1.0","findings":[{"asset":"x","title":"x","external_id":"scanner:x","cvss_score":NaN}]}',
            "scan.json",
            "generic-json",
        ),
        (b"x" * (2 * 1024 * 1024 + 1), "scan.json", "generic-json"),
        (b"[" * 2000, "scan.json", "generic-json"),
    ],
)
def test_malformed_and_malicious_imports(content, filename, adapter):
    with pytest.raises(ImportError):
        parse_import(adapter, content, filename)


def test_csv_and_untrusted_text(imported):
    client, _ = imported
    content = 'asset,title,external_id,cvss_score\nSERVER-01,=HYPERLINK("evil"),scanner:csv,8.2\n'
    response = client.post("/api/imports?adapter=generic-csv", files={"file": ("scan.csv", content)})
    assert response.status_code == 201
    export = client.get("/api/reports/export")
    assert "'=HYPERLINK" in export.text
    assert export.headers["Content-Disposition"].endswith('"vulnwatch-findings.csv"')


def test_invalid_cvss_unknown_fields_and_rows():
    for extra in [{"cvss_score": 11}, {"cvss_score": -1}, {"execute": "anything"}, {"cve_id": "not-a-cve"}]:
        row = {"asset": "server", "title": "test", "external_id": "scanner:test", **extra}
        with pytest.raises(ImportError):
            parse_import(
                "generic-json", json.dumps({"schema_version": "1.0", "findings": [row]}).encode(), "scan.json"
            )


def test_filter_search_is_not_sql(imported):
    client, _ = imported
    assert client.get("/api/findings", params={"q": "' OR 1=1 --"}).json()["total"] == 0
    assert client.get("/api/findings", params={"q": "%"}).json()["total"] == 0
    assert client.get("/api/findings?severity_level=critical").json()["total"] == 1


def test_control_bytes_are_rejected_and_upload_names_are_safe(authenticated):
    client = authenticated()
    assert (
        client.post("/api/assets", json={"name": "safe-asset", "owner": "unsafe\u0000name"}).status_code
        == 422
    )
    response = client.post(
        "/api/imports?adapter=generic-json", files={"file": ("../../bad\x00name.json", b"invalid")}
    )
    assert response.status_code == 422
    job = client.get("/api/imports").json()[0]
    assert job["filename"] == "bad%00name.json"
    body = b'--boundary\r\nContent-Disposition: form-data; name="file"; filename="../../bad\x00name.json"\r\nContent-Type: application/json\r\n\r\ninvalid\r\n--boundary--\r\n'
    response = client.post(
        "/api/imports?adapter=generic-json",
        content=body,
        headers={"Content-Type": "multipart/form-data; boundary=boundary"},
    )
    assert response.status_code == 422
    assert client.get("/api/imports").json()[0]["filename"] == "bad_name.json"
