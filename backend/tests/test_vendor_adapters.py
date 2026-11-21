import json
from pathlib import Path

import pytest

from app.adapters import ADAPTERS, ImportError, parse_import

SAMPLES = Path(__file__).parents[2] / "samples"


def sample(name):
    return (SAMPLES / name).read_bytes()


def test_all_adapters_declare_contract():
    for key, adapter in ADAPTERS.items():
        assert adapter.extension in {".json", ".csv"}
        assert adapter.schema_version
        assert adapter.documentation.startswith("docs/imports.md#"), key
        assert isinstance(adapter.requires_asset, bool)


def test_only_vendor_adapters_require_an_asset():
    assert ADAPTERS["generic-json"].requires_asset is False
    assert ADAPTERS["generic-csv"].requires_asset is False
    assert ADAPTERS["trivy-json"].requires_asset is True
    assert ADAPTERS["grype-json"].requires_asset is True
    assert ADAPTERS["dependency-check-json"].requires_asset is True


def test_trivy_mapping():
    rows = parse_import("trivy-json", sample("trivy.json"), "trivy.json", "payments-api")
    assert len(rows) == 4
    log4j = next(row for row in rows if row.cve_id == "CVE-2024-21538")
    assert log4j.source == "trivy"
    assert log4j.locator == "pkg:cross-spawn@7.0.3"
    assert log4j.cvss_score == 7.5
    advisory = next(row for row in rows if row.external_id)
    assert advisory.external_id == "ghsa:GHSA-3xgq-45jj-v275"
    assert advisory.cve_id is None
    assert advisory.cvss_score is None
    openssl = next(row for row in rows if row.cve_id == "CVE-2024-9143")
    assert openssl.cvss_score == 3.7


def test_trivy_cvss_prefers_highest_version_across_sources():
    payload = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1111",
                        "PkgName": "pkg",
                        "CVSS": {
                            "mixed": {"V40Score": 4.4, "V3Score": 9.9, "V2Score": 5.0},
                            "v3only": {"V3Score": 8.8},
                        },
                    },
                    {
                        "VulnerabilityID": "CVE-2024-2222",
                        "PkgName": "pkg",
                        "CVSS": {"v2only": {"V2Score": 5.0}},
                    },
                    {
                        "VulnerabilityID": "CVE-2024-3333",
                        "PkgName": "pkg",
                        "CVSS": {"bad": {"V3Score": 42}},
                    },
                ]
            }
        ],
    }
    rows = parse_import("trivy-json", json.dumps(payload).encode(), "t.json", "server-01")
    by_cve = {row.cve_id: row.cvss_score for row in rows}
    assert by_cve["CVE-2024-1111"] == 4.4
    assert by_cve["CVE-2024-2222"] == 5.0
    assert by_cve["CVE-2024-3333"] is None


def test_trivy_duplicate_cve_keeps_distinct_locators():
    rows = parse_import("trivy-json", sample("trivy.json"), "trivy.json", "payments-api")
    same_cve = [row for row in rows if row.cve_id == "CVE-2024-21538"]
    assert len(same_cve) == 2
    assert {row.locator for row in same_cve} == {"pkg:cross-spawn@7.0.3"}


def test_grype_mapping():
    rows = parse_import("grype-json", sample("grype.json"), "grype.json", "analytics-api")
    assert len(rows) == 2
    critical = next(row for row in rows if row.cve_id == "CVE-2023-45853")
    assert critical.cvss_score == 9.8
    assert critical.locator == "pkg:zlib@1.3-r0"
    assert critical.source == "grype"
    assert critical.asset == "analytics-api"
    medium = next(row for row in rows if row.cve_id == "CVE-2024-28849")
    assert medium.cvss_score == 6.5
    assert medium.locator == "pkg:follow-redirects@1.15.4"


def test_dependency_check_mapping_and_empty_dependency():
    rows = parse_import("dependency-check-json", sample("dependency-check.json"), "dc.json", "order-service")
    assert len(rows) == 3
    log4shell = next(row for row in rows if row.cve_id == "CVE-2021-44228")
    assert log4shell.cvss_score == 10.0
    assert log4shell.locator == "pkg:log4j-core-2.14.1.jar"
    assert log4shell.source == "dependency-check"
    spring = next(row for row in rows if row.cve_id == "CVE-2022-22965")
    assert spring.cvss_score == 9.8


def test_vendor_adapters_require_existing_asset_name():
    for name, filename in [
        ("trivy-json", "trivy.json"),
        ("grype-json", "grype.json"),
        ("dependency-check-json", "dependency-check.json"),
    ]:
        with pytest.raises(ImportError):
            parse_import(name, sample(filename), filename)
        with pytest.raises(ImportError):
            parse_import(name, sample(filename), filename, "-bad asset-")


def test_cross_adapter_cve_identity_is_shared():
    trivy = parse_import("trivy-json", sample("trivy.json"), "trivy.json", "payments-api")
    grype = parse_import("grype-json", sample("grype.json"), "grype.json", "analytics-api")
    payload = {
        "schema_version": "1.0",
        "findings": [
            {"asset": "payments-api", "cve_id": row.cve_id, "title": "x", "locator": row.locator}
            for row in trivy
            if row.cve_id
        ]
        + [{"asset": "analytics-api", "cve_id": row.cve_id, "title": "x"} for row in grype],
    }
    rows = parse_import("generic-json", json.dumps(payload).encode(), "scan.json")
    assert {row.cve_id for row in rows} == {
        "CVE-2024-9143",
        "CVE-2024-21538",
        "CVE-2023-45853",
        "CVE-2024-28849",
    }


@pytest.mark.parametrize(
    "adapter,content,filename",
    [
        ("trivy-json", b"<script>alert(1)</script>", "t.json"),
        ("trivy-json", b'{"SchemaVersion":1,"Results":[]}', "t.json"),
        ("trivy-json", b'{"SchemaVersion":2,"Results":{}}', "t.json"),
        (
            "trivy-json",
            b'{"SchemaVersion":2,"Results":[{"Vulnerabilities":[{"VulnerabilityID":""}]}]}',
            "t.json",
        ),
        ("grype-json", b'{"matches":[{"vulnerability":{},"artifact":{}}]}', "g.json"),
        ("grype-json", b'{"matches":"nope"}', "g.json"),
        ("dependency-check-json", b'{"dependencies":[]}', "d.json"),
        (
            "dependency-check-json",
            b'{"reportSchema":"1.1","dependencies":[{"vulnerabilities":[{"name":"CVE-2021-44228","cvssv3":1}]}]}',
            "d.json",
        ),
        ("trivy-json", b"[" * 2000, "t.json"),
        ("grype-json", b"x" * (2 * 1024 * 1024 + 1), "g.json"),
        ("trivy-json", b'{"SchemaVersion":2,"SchemaVersion":2,"Results":[]}', "t.json"),
        (
            "trivy-json",
            b'{"SchemaVersion":2,"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2021-44228","PkgName":"pkg","CVSS":{"x":{"V3Score":NaN}}}]}]}',
            "t.json",
        ),
    ],
)
def test_vendor_malformed_and_malicious(adapter, content, filename):
    with pytest.raises(ImportError):
        parse_import(adapter, content, filename, "server-01")


def test_vendor_control_bytes_and_asset_validation():
    payload = json.loads(sample("grype.json"))
    payload["matches"][0]["vulnerability"]["description"] = "bad\x00description"
    with pytest.raises(ImportError):
        parse_import("grype-json", json.dumps(payload).encode(), "g.json", "server-01")
    with pytest.raises(ImportError):
        parse_import("grype-json", sample("grype.json"), "g.json", "server\u0000name")


def test_vendor_row_limit_is_enforced():
    payload = json.loads(sample("trivy.json"))
    template = payload["Results"][0]["Vulnerabilities"][0]
    payload["Results"][0]["Vulnerabilities"] = [
        {**template, "VulnerabilityID": f"CVE-2024-{10000 + index}"} for index in range(1001)
    ]
    payload["Results"] = payload["Results"][:1]
    with pytest.raises(ImportError):
        parse_import("trivy-json", json.dumps(payload).encode(), "t.json", "server-01")


def test_unknown_adapter_and_extension_still_rejected():
    with pytest.raises(ImportError):
        parse_import("nessus-xml", b"{}", "scan.json", "server-01")
    with pytest.raises(ImportError):
        parse_import("trivy-json", sample("trivy.json"), "trivy.xml", "server-01")


def test_adapter_contracts_are_listed(authenticated):
    client = authenticated()
    contracts = {item["id"]: item for item in client.get("/api/imports/adapters").json()}
    assert set(contracts) == {
        "generic-json",
        "generic-csv",
        "trivy-json",
        "grype-json",
        "dependency-check-json",
    }
    assert contracts["trivy-json"]["schema_version"] == "2"
    assert contracts["trivy-json"]["requires_asset"] is True
    assert contracts["dependency-check-json"]["schema_version"] == "1.1"
    assert contracts["generic-json"]["requires_asset"] is False
    for contract in contracts.values():
        assert contract["documentation"].startswith("docs/imports.md#")


def test_vendor_import_through_api_and_cross_adapter_dedup(imported):
    client, _ = imported
    generic = {
        "schema_version": "1.0",
        "findings": [
            {
                "asset": "server-01",
                "cve_id": "CVE-2021-44228",
                "title": "Log4Shell observed by a host scanner",
                "cvss_score": 10,
                "locator": "pkg:log4j-core@2.14.1",
                "source": "other-scanner",
            }
        ],
    }
    assert (
        client.post(
            "/api/imports?adapter=generic-json", files={"file": ("host.json", json.dumps(generic))}
        ).json()["created"]
        == 1
    )
    payload = json.loads(sample("grype.json"))
    payload["matches"] = [
        {
            "vulnerability": {
                "id": "CVE-2021-44228",
                "description": "Same CVE observed by a container scan.",
                "cvss": [{"metrics": {"baseScore": 10.0}}],
            },
            "artifact": {"name": "log4j-core", "version": "2.14.1"},
        },
        {
            "vulnerability": {"id": "CVE-2023-45853", "description": "New CVE from Grype."},
            "artifact": {"name": "zlib", "version": "1.3-r0"},
        },
    ]
    response = client.post(
        "/api/imports?adapter=grype-json&asset=server-01",
        files={"file": ("grype.json", json.dumps(payload))},
    )
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "completed"
    assert response.json()["created"] == 1
    assert response.json()["duplicates"] == 1
    observed = [
        item
        for item in client.get("/api/findings", params={"q": "CVE-2021-44228"}).json()["items"]
        if item["locator"] == "pkg:log4j-core@2.14.1"
    ]
    assert len(observed) == 1
    assert observed[0]["occurrences"] == 2
    assert client.get("/api/findings").json()["total"] == 3


def test_vendor_import_requires_asset_and_reports_safe_failure(imported):
    client, _ = imported
    response = client.post(
        "/api/imports?adapter=trivy-json",
        files={"file": ("trivy.json", sample("trivy.json"))},
    )
    assert response.status_code == 422
    assert "target asset" in response.json()["detail"]
    failed = client.get("/api/imports").json()[0]
    assert failed["adapter"] == "trivy-json"
    assert failed["status"] == "failed"
    assert "target asset" in failed["error"]


def test_vendor_import_rejects_unknown_asset_atomically(imported, database):
    from sqlalchemy import func, select

    from app.models import Finding

    client, _ = imported
    response = client.post(
        "/api/imports?adapter=dependency-check-json&asset=missing-server",
        files={"file": ("dependency-check.json", sample("dependency-check.json"))},
    )
    assert response.status_code == 422
    with database() as db:
        assert db.scalar(select(func.count(Finding.id))) == 1
