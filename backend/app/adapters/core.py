import csv
import io
import json
from typing import Protocol

from pydantic import ValidationError

from app.schemas import ImportRow

MAX_BYTES = 2 * 1024 * 1024
MAX_ROWS = 1000


class ImportError(ValueError):
    pass


class Adapter(Protocol):
    extension: str
    schema_version: str
    documentation: str
    requires_asset: bool

    def parse(self, text: str, asset: str) -> list[dict]: ...


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ImportError("Duplicate JSON keys are not permitted")
        result[key] = value
    return result


def reject_constant(value):
    raise ImportError("Non-finite numbers are not permitted")


def load_object(text):
    payload = json.loads(text, object_pairs_hook=unique_keys, parse_constant=reject_constant)
    if not isinstance(payload, dict):
        raise ImportError("Expected a JSON object")
    return payload


class GenericJSON:
    extension = ".json"
    schema_version = "1.0"
    documentation = "docs/imports.md#json-generic-json"
    requires_asset = False

    def parse(self, text, asset):
        payload = load_object(text)
        if set(payload) != {"schema_version", "findings"} or payload["schema_version"] != "1.0":
            raise ImportError("Expected schema_version 1.0 and findings array")
        if not isinstance(payload["findings"], list):
            raise ImportError("findings must be an array")
        return payload["findings"]


class GenericCSV:
    extension = ".csv"
    schema_version = "1.0"
    documentation = "docs/imports.md#csv-generic-csv"
    requires_asset = False

    def parse(self, text, asset):
        reader = csv.DictReader(io.StringIO(text), strict=True)
        headers = reader.fieldnames or []
        if len(headers) != len(set(headers)) or not {"asset", "title"} <= set(headers):
            raise ImportError("CSV requires unique headers including asset and title")
        if set(headers) - set(ImportRow.model_fields):
            raise ImportError("Unknown CSV columns")
        rows = []
        for row in reader:
            if len(rows) >= MAX_ROWS:
                raise ImportError("Maximum 1000 findings per import")
            if None in row or any(value is None for value in row.values()):
                raise ImportError("CSV row width does not match header")
            rows.append({key: value for key, value in row.items() if value != ""})
        return rows


def validate_rows(raw_rows):
    if not 1 <= len(raw_rows) <= MAX_ROWS:
        raise ImportError("Import must contain 1–1000 findings")
    result = []
    for index, row in enumerate(raw_rows, start=1):
        try:
            result.append(ImportRow.model_validate(row))
        except ValidationError:
            raise ImportError(f"Invalid finding at row {index}; check documented schema") from None
    return result
