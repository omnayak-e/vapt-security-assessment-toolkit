from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

@dataclass
class Finding:
    title: str
    severity: str
    asset: str
    description: str
    evidence: str
    remediation: str
    category: str = "Configuration"
    verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass
class Assessment:
    target: str
    started_at: str
    tool: str
    findings: list[Finding]
    notes: list[str]

    @classmethod
    def create(cls, target: str, findings: list[Finding], notes=None):
        return cls(
            target=target,
            started_at=datetime.now(timezone.utc).isoformat(),
            tool="VAPT Security Assessment Toolkit",
            findings=findings,
            notes=notes or [],
        )

    def to_dict(self):
        return {
            "target": self.target,
            "started_at": self.started_at,
            "tool": self.tool,
            "findings": [f.to_dict() for f in self.findings],
            "notes": self.notes,
        }
