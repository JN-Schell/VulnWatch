import httpx
import pytest
from sqlalchemy import select

from app.models import CVERecord, SyncState
from app.nvd import NVDClient, NVDError, extract_cve, synchronize, upsert_cve


def fixture_cve(**overrides):
    return {
        "id": "CVE-2021-44228",
        "published": "2021-12-10T10:15:09.143",
        "lastModified": "2026-11-01T12:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "Fixture description, not a live NVD response"}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "baseScore": 10,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    },
                }
            ]
        },
        "references": [{"url": "https://logging.apache.org/security.html"}, {"url": "javascript:alert(1)"}],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                                "versionEndExcluding": "2.15.0",
                            }
                        ]
                    }
                ]
            }
        ],
        **overrides,
    }


def test_ingestion_optional_fields_and_cvss_versions(database):
    values = extract_cve(fixture_cve())
    assert values["cvss_score"] == 10
    assert values["severity"] == "critical"
    assert len(values["references"]) == 1
    assert values["affected_products"][0]["versionEndExcluding"] == "2.15.0"
    assert extract_cve(fixture_cve(metrics={}))["cvss_score"] is None
    v2 = fixture_cve(metrics={"cvssMetricV2": [{"cvssData": {"version": "2.0", "baseScore": 10}}]})
    assert extract_cve(v2)["severity"] == "high"
    assert extract_cve(fixture_cve(vulnStatus="Rejected"))["cvss_score"] is None
    with database() as db:
        upsert_cve(db, fixture_cve())
        upsert_cve(db, fixture_cve())
        db.commit()
        assert len(list(db.scalars(select(CVERecord)))) == 1


@pytest.mark.parametrize("status", [403, 429, 503])
def test_external_failures(status):
    attempts = []

    def handler(request):
        attempts.append(request)
        return httpx.Response(status, json={"error": "not available"})

    client = NVDClient(transport=httpx.MockTransport(handler), sleep=lambda _: None)
    with pytest.raises(NVDError):
        client.request({"cveId": "CVE-2021-44228"})
    assert len(attempts) == (1 if status == 403 else 3)
    client.close()


def test_pagination_and_retries(database):
    attempts = []

    def handler(request):
        attempts.append(request)
        if len(attempts) == 1:
            return httpx.Response(429, headers={"Retry-After": "1"})
        index = int(request.url.params["startIndex"])
        cve = fixture_cve(id=f"CVE-2026-{1000 + index}")
        return httpx.Response(
            200, json={"totalResults": 2, "startIndex": index, "vulnerabilities": [{"cve": cve}]}
        )

    client = NVDClient(transport=httpx.MockTransport(handler), sleep=lambda _: None)
    assert synchronize(client)
    with database() as db:
        assert len(list(db.scalars(select(CVERecord)))) == 2
        assert db.get(SyncState, 1).watermark is not None
        assert db.get(SyncState, 1).lease_until is None
    client.close()


def test_failed_sync_does_not_advance_cursor(database):
    client = NVDClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(503)), sleep=lambda _: None
    )
    assert not synchronize(client)
    with database() as db:
        assert db.get(SyncState, 1).watermark is None
        assert db.get(SyncState, 1).last_error is not None
    client.close()


def test_failed_later_page_rolls_back_entire_window(database):
    def handler(request):
        if request.url.params["startIndex"] == "0":
            return httpx.Response(
                200, json={"totalResults": 2, "startIndex": 0, "vulnerabilities": [{"cve": fixture_cve()}]}
            )
        return httpx.Response(503)

    client = NVDClient(transport=httpx.MockTransport(handler), sleep=lambda _: None)
    assert not synchronize(client)
    with database() as db:
        assert list(db.scalars(select(CVERecord))) == []
        assert db.get(SyncState, 1).watermark is None
    client.close()


def test_postgres_sync_lock_excludes_another_worker(database):
    from sqlalchemy import text

    from app import nvd

    if nvd.engine.dialect.name != "postgresql":
        pytest.skip("PostgreSQL advisory-lock integration test")
    with nvd.engine.connect() as connection:
        assert connection.scalar(text("SELECT pg_try_advisory_lock(86174921)"))
        try:
            assert not synchronize(client=object())
        finally:
            connection.execute(text("SELECT pg_advisory_unlock(86174921)"))


def test_malformed_response_and_timeout():
    client = NVDClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"unexpected": True})),
        sleep=lambda _: None,
    )
    with pytest.raises(NVDError):
        client.request({})
    client.close()

    def timeout(request):
        raise httpx.ReadTimeout("timeout", request=request)

    client = NVDClient(transport=httpx.MockTransport(timeout), sleep=lambda _: None)
    with pytest.raises(NVDError):
        client.request({})
    client.close()


def test_enrichment_updates_existing_import(imported):
    client, _ = imported
    from app import api

    with api.SessionLocal() as db:
        upsert_cve(
            db,
            fixture_cve(
                metrics={
                    "cvssMetricV40": [{"type": "Primary", "cvssData": {"version": "4.0", "baseScore": 8.7}}]
                }
            ),
        )
        db.commit()
    finding = client.get("/api/findings").json()["items"][0]
    assert finding["cvss_score"] == 8.7
    assert finding["score_source"] == "nvd"
