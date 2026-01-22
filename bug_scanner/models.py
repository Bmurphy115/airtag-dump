"""
Database models for the bug scanner.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Bug severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class BugCategory(Enum):
    """Bug category classifications."""
    BUFFER_OVERFLOW = "buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    INTEGER_OVERFLOW = "integer_overflow"
    FORMAT_STRING = "format_string"
    COMMAND_INJECTION = "command_injection"
    MEMORY_LEAK = "memory_leak"
    NULL_POINTER = "null_pointer"
    RACE_CONDITION = "race_condition"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    CRYPTOGRAPHIC_WEAKNESS = "cryptographic_weakness"
    HARDCODED_CREDENTIALS = "hardcoded_credentials"
    INFORMATION_DISCLOSURE = "information_disclosure"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNINITIALIZED_MEMORY = "uninitialized_memory"
    OTHER = "other"


class BugStatus(Enum):
    """Bug status tracking."""
    OPEN = "open"
    CONFIRMED = "confirmed"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    WONT_FIX = "wont_fix"
    DUPLICATE = "duplicate"


@dataclass
class Bug:
    """Represents a bug/vulnerability entry in the database."""
    id: Optional[int]
    name: str
    description: str
    severity: Severity
    category: BugCategory
    status: BugStatus
    affected_component: str
    pattern: Optional[str]  # Regex or byte pattern for detection
    cve_id: Optional[str]
    cvss_score: Optional[float]
    memory_address: Optional[str]  # Hex address where bug was found
    firmware_version: Optional[str]
    discovery_date: datetime
    last_updated: datetime
    notes: Optional[str]

    def to_dict(self) -> dict:
        """Convert bug to dictionary representation."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "status": self.status.value,
            "affected_component": self.affected_component,
            "pattern": self.pattern,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "memory_address": self.memory_address,
            "firmware_version": self.firmware_version,
            "discovery_date": self.discovery_date.isoformat(),
            "last_updated": self.last_updated.isoformat(),
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Bug":
        """Create a Bug instance from a dictionary."""
        return cls(
            id=data.get("id"),
            name=data["name"],
            description=data["description"],
            severity=Severity(data["severity"]),
            category=BugCategory(data["category"]),
            status=BugStatus(data["status"]),
            affected_component=data["affected_component"],
            pattern=data.get("pattern"),
            cve_id=data.get("cve_id"),
            cvss_score=data.get("cvss_score"),
            memory_address=data.get("memory_address"),
            firmware_version=data.get("firmware_version"),
            discovery_date=datetime.fromisoformat(data["discovery_date"]),
            last_updated=datetime.fromisoformat(data["last_updated"]),
            notes=data.get("notes"),
        )


@dataclass
class ScanResult:
    """Represents a scan result when searching for bugs."""
    bug: Bug
    match_location: Optional[str]
    match_context: Optional[str]
    confidence: float  # 0.0 to 1.0

    def to_dict(self) -> dict:
        """Convert scan result to dictionary."""
        return {
            "bug": self.bug.to_dict(),
            "match_location": self.match_location,
            "match_context": self.match_context,
            "confidence": self.confidence,
        }
