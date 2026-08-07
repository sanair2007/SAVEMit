from dataclasses import dataclass, field

@dataclass
class InvestigationCase:
    id: str
    repository: str

    stage: str = "NEW"
    status: str = "PENDING"

    findings: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    history: list = field(default_factory=list)
