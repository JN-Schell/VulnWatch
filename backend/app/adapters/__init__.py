import csv

from app.adapters.core import (
    MAX_BYTES,
    MAX_ROWS,
    Adapter,
    GenericCSV,
    GenericJSON,
    ImportError,
    validate_rows,
)
from app.adapters.vendor import DependencyCheckJSON, GrypeJSON, TrivyJSON

ADAPTERS: dict[str, Adapter] = {
    "generic-json": GenericJSON(),
    "generic-csv": GenericCSV(),
    "trivy-json": TrivyJSON(),
    "grype-json": GrypeJSON(),
    "dependency-check-json": DependencyCheckJSON(),
}


def parse_import(adapter_name, content, filename, asset=""):
    adapter = ADAPTERS.get(adapter_name)
    if not adapter:
        raise ImportError("Unknown import adapter")
    if not filename.lower().endswith(adapter.extension):
        raise ImportError("Filename extension does not match adapter")
    if len(content) > MAX_BYTES:
        raise ImportError("Maximum upload size is 2 MiB")
    if adapter.requires_asset and not asset.strip():
        raise ImportError("This adapter requires an existing target asset")
    try:
        text = content.decode("utf-8-sig")
        if "\x00" in text:
            raise ImportError("NUL bytes are not permitted")
        raw_rows = adapter.parse(text, asset.strip().lower())
        return validate_rows(raw_rows)
    except ImportError:
        raise
    except (UnicodeError, ValueError, csv.Error, RecursionError, TypeError):
        raise ImportError("Malformed import; expected strict UTF-8 JSON or CSV") from None


__all__ = [
    "ADAPTERS",
    "MAX_BYTES",
    "MAX_ROWS",
    "Adapter",
    "GenericCSV",
    "GenericJSON",
    "ImportError",
    "parse_import",
]
