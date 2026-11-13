import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, allow_inf_nan=False)

    @field_validator("*", mode="after")
    @classmethod
    def reject_control_bytes(cls, value):
        if isinstance(value, str) and re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", value):
            raise ValueError("Control characters are not allowed")
        return value


class Login(StrictModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class UserCreate(StrictModel):
    email: str = Field(pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$", max_length=254)
    name: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=14, max_length=128)
    role: Literal["admin", "analyst", "viewer"]


class AssetInput(StrictModel):
    name: str = Field(min_length=1, max_length=200, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._:/-]*$")
    category: str = Field(default="Server", min_length=1, max_length=100)
    criticality: int = Field(default=3, ge=1, le=5)
    exposure: Literal["internal", "internet"] = "internal"
    owner: str = Field(default="", max_length=100)

    @field_validator("name")
    @classmethod
    def canonical_name(cls, value):
        return value.lower()


class ImportRow(StrictModel):
    asset: str = Field(min_length=1, max_length=200, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._:/-]*$")
    title: str = Field(min_length=1, max_length=300)
    cve_id: str | None = Field(default=None, pattern=r"^CVE-\d{4}-\d{4,19}$", max_length=30)
    external_id: str | None = Field(
        default=None, pattern=r"^[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.:/-]+$", max_length=200
    )
    description: str = Field(default="", max_length=10000)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    locator: str = Field(default="", max_length=200)
    source: str = Field(default="generic", min_length=1, max_length=100)

    @field_validator("asset")
    @classmethod
    def canonical_asset(cls, value):
        return value.lower()

    @field_validator("title", "description", "locator", "source")
    @classmethod
    def no_controls(cls, value):
        if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", value):
            raise ValueError("Control characters are not allowed")
        return value

    @model_validator(mode="after")
    def identity(self):
        if not self.cve_id and not self.external_id:
            raise ValueError("cve_id or namespace-qualified external_id is required")
        return self


class FindingUpdate(StrictModel):
    revision: int = Field(ge=1)
    status: Literal["open", "in_progress", "mitigated", "verified", "accepted"] | None = None
    assignee_id: int | None = Field(default=None, ge=1)
    due_at: datetime | None = None
    note: str = Field(min_length=1, max_length=5000)
    kind: Literal["note", "mitigation", "verification"] = "note"

    @field_validator("due_at")
    @classmethod
    def aware_deadline(cls, value):
        if value is not None and value.tzinfo is None:
            raise ValueError("Deadline must include a timezone")
        return value


class PolicyInput(StrictModel):
    low: float = Field(default=0.1, gt=0, le=10)
    medium: float = Field(default=4, gt=0, le=10)
    high: float = Field(default=7, gt=0, le=10)
    critical: float = Field(default=9, gt=0, le=10)
    internet_multiplier: float = Field(default=1.25, ge=1, le=2)
    unknown_baseline: float = Field(default=5, ge=0, le=10)

    @model_validator(mode="after")
    def ordered(self):
        if not self.low < self.medium < self.high < self.critical:
            raise ValueError("Severity thresholds must be strictly increasing")
        return self
