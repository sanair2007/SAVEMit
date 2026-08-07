from pathlib import Path

from fastapi import FastAPI, HTTPException

app = FastAPI(title="SAVEMit")


@app.get("/health")
def health():
    return {
        "status": "ok"
    }

from app.coordinator.coordinator import InvestigationCoordinator
from app.models.investigation_case import InvestigationCase


@app.get("/test")
def test():

    case = InvestigationCase(
        id="1",
        repository=str(Path(__file__).resolve().parents[2])
    )

    coordinator = InvestigationCoordinator()

    try:
        result = coordinator.run(case)
    except (RuntimeError, ValueError) as error:
        raise HTTPException(status_code=500, detail=str(error)) from error

    threat_intel = result.metadata.get("threat_intel", {})

    return {
        "repository": result.repository,
        "stage": result.stage,
        "status": result.status,
        "history": result.history,
        "sbom_package_count": result.metadata.get("sbom_package_count", 0),
        "raw_vulnerability_count": threat_intel.get(
            "raw_vulnerability_count", 0
        ),
        "vulnerability_count": threat_intel.get("vulnerability_count", 0),
        "priority_summary": result.metadata.get("policy", {}).get("summary", {}),
        "findings": threat_intel.get("vulnerabilities", []),
    }
