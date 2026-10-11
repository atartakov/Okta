from __future__ import annotations

from dataclasses import dataclass, asdict

SEVERITIES = ["info", "low", "medium", "high", "critical"]


def sev_rank(sev: str) -> int:
    return SEVERITIES.index(sev)


@dataclass
class Finding:
    rule_id: str
    severity: str
    address: str
    title: str
    detail: str
    recommendation: str

    def to_dict(self) -> dict:
        return asdict(self)
