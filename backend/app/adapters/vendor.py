import math
import re

from app.adapters.core import MAX_ROWS, ImportError, load_object

CVE = re.compile(r"^CVE-\d{4}-\d{4,19}$")
GHSA = re.compile(r"^GHSA(-[0-9a-z]{4}){3}$")
ASSET = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:/-]*$")


def _text(value, limit):
    return value[:limit] if isinstance(value, str) else ""


def _title(value, fallback):
    text = _text(value, 300)
    return text if text.strip() else fallback


def _identifier(value):
    return value.strip() if isinstance(value, str) else ""


def _score(*candidates):
    for candidate in candidates:
        if isinstance(candidate, bool) or not isinstance(candidate, (int, float)):
            continue
        if math.isfinite(candidate) and 0 <= candidate <= 10:
            return float(candidate)
    return None


def _identity(namespace, raw_id):
    if CVE.match(raw_id):
        return raw_id, None
    if GHSA.match(raw_id):
        return None, f"ghsa:{raw_id}"
    return None, f"{namespace}:{raw_id}"


def _target_asset(asset):
    name = (asset or "").strip()
    if not ASSET.match(name) or len(name) > 200:
        raise ImportError("Vendor adapters require a canonical target asset name")
    return name


def _locator(package, version):
    value = f"pkg:{package}@{version}" if version else f"pkg:{package}"
    return value[:200]


def _require_list(payload, key):
    value = payload.get(key)
    if not isinstance(value, list):
        raise ImportError(f"Expected a {key} array")
    return value


def _require_dict(value):
    if not isinstance(value, dict):
        raise ImportError("Expected each finding to be a JSON object")
    return value


def _optional_dict(value, field):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ImportError(f"Expected {field} to be an object")
    return value


class TrivyJSON:
    extension = ".json"
    schema_version = "2"
    requires_asset = True
    documentation = "docs/imports.md#trivy-json-trivy-json"

    def parse(self, text, asset):
        target = _target_asset(asset)
        payload = load_object(text)
        if payload.get("SchemaVersion") != 2:
            raise ImportError("Expected a Trivy JSON report with SchemaVersion 2")
        rows = []
        for result in _require_list(payload, "Results"):
            result = _require_dict(result)
            vulnerabilities = result.get("Vulnerabilities") or []
            if not isinstance(vulnerabilities, list):
                raise ImportError("Expected Vulnerabilities to be an array")
            for entry in vulnerabilities:
                entry = _require_dict(entry)
                vendor_id = _identifier(entry.get("VulnerabilityID"))
                package = _identifier(entry.get("PkgName"))
                if not vendor_id or not package:
                    raise ImportError("Trivy findings require VulnerabilityID and PkgName")
                cve_id, external_id = _identity("trivy", vendor_id)
                cvss = _optional_dict(entry.get("CVSS"), "CVSS")
                scores = [value for value in cvss.values() if isinstance(value, dict)]
                rows.append(
                    {
                        "asset": target,
                        "title": _title(entry.get("Title"), vendor_id),
                        "cve_id": cve_id,
                        "external_id": external_id,
                        "description": _text(entry.get("Description"), 10000),
                        "cvss_score": _score(
                            *(
                                value.get(field)
                                for value in scores
                                for field in ("V40Score", "V3Score", "V2Score")
                            )
                        ),
                        "locator": _locator(package, _identifier(entry.get("InstalledVersion"))),
                        "source": "trivy",
                    }
                )
                if len(rows) > MAX_ROWS:
                    raise ImportError("Maximum 1000 findings per import")
        return rows


class GrypeJSON:
    extension = ".json"
    schema_version = "grype-json"
    requires_asset = True
    documentation = "docs/imports.md#grype-json-grype-json"

    def parse(self, text, asset):
        target = _target_asset(asset)
        payload = load_object(text)
        rows = []
        for match in _require_list(payload, "matches"):
            match = _require_dict(match)
            vulnerability = _require_dict(match.get("vulnerability"))
            artifact = _require_dict(match.get("artifact"))
            vendor_id = _identifier(vulnerability.get("id"))
            package = _identifier(artifact.get("name"))
            if not vendor_id or not package:
                raise ImportError("Grype matches require vulnerability.id and artifact.name")
            cve_id, external_id = _identity("grype", vendor_id)
            cvss = vulnerability.get("cvss")
            if cvss is None:
                cvss = []
            if not isinstance(cvss, list):
                raise ImportError("Expected Grype cvss to be an array")
            base_scores = [
                entry["metrics"].get("baseScore")
                for entry in cvss
                if isinstance(entry, dict) and isinstance(entry.get("metrics"), dict)
            ]
            rows.append(
                {
                    "asset": target,
                    "title": _title(vulnerability.get("description"), vendor_id),
                    "cve_id": cve_id,
                    "external_id": external_id,
                    "description": _text(vulnerability.get("description"), 10000),
                    "cvss_score": _score(*base_scores),
                    "locator": _locator(package, _identifier(artifact.get("version"))),
                    "source": "grype",
                }
            )
            if len(rows) > MAX_ROWS:
                raise ImportError("Maximum 1000 findings per import")
        return rows


class DependencyCheckJSON:
    extension = ".json"
    schema_version = "1.1"
    requires_asset = True
    documentation = "docs/imports.md#owasp-dependency-check-json-dependency-check-json"

    def parse(self, text, asset):
        target = _target_asset(asset)
        payload = load_object(text)
        if not isinstance(payload.get("reportSchema"), str):
            raise ImportError("Expected a Dependency-Check report with reportSchema")
        rows = []
        for dependency in _require_list(payload, "dependencies"):
            dependency = _require_dict(dependency)
            vulnerabilities = dependency.get("vulnerabilities") or []
            if not isinstance(vulnerabilities, list):
                raise ImportError("Expected vulnerabilities to be an array")
            package = _identifier(dependency.get("fileName")) or "unknown"
            for entry in vulnerabilities:
                entry = _require_dict(entry)
                vendor_id = _identifier(entry.get("name"))
                if not vendor_id:
                    raise ImportError("Dependency-Check findings require a vulnerability name")
                cve_id, external_id = _identity("dependency-check", vendor_id)
                cvss_v2 = _optional_dict(entry.get("cvssv2"), "cvssv2")
                cvss_v3 = _optional_dict(entry.get("cvssv3"), "cvssv3")
                cvss_v4 = _optional_dict(entry.get("cvssv4"), "cvssv4")
                rows.append(
                    {
                        "asset": target,
                        "title": _title(entry.get("name"), vendor_id),
                        "cve_id": cve_id,
                        "external_id": external_id,
                        "description": _text(entry.get("description"), 10000),
                        "cvss_score": _score(
                            cvss_v4.get("baseScore"),
                            cvss_v3.get("baseScore"),
                            cvss_v2.get("score"),
                        ),
                        "locator": _locator(package, ""),
                        "source": "dependency-check",
                    }
                )
                if len(rows) > MAX_ROWS:
                    raise ImportError("Maximum 1000 findings per import")
        return rows
