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


DEMO_REPOSITORIES = Path(__file__).resolve().parents[2] / "reference-repos"


@app.get("/demo-repositories")
def demo_repositories():
    return {
        "repositories": [
            "customer-portal",
            "breaking-upgrade",
            "unsupported-python-service",
            "unreachable-dependency",
            "tests-not-defined",
            "policy-blocked-upgrade",
            "no-fix-available",
            "docker-unavailable",
            "transitive-dependency",
        ]
    }


@app.get("/test")
def test(repository: str = "customer-portal"):
    repository_path = (DEMO_REPOSITORIES / repository).resolve()
    if DEMO_REPOSITORIES.resolve() not in repository_path.parents:
        raise HTTPException(status_code=400, detail="Choose a repository from /demo-repositories.")
    if not repository_path.is_dir():
        raise HTTPException(status_code=404, detail=f"Demo repository '{repository}' was not found.")

    case = InvestigationCase(id="1", repository=str(repository_path))

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
        "sbom_source": result.metadata.get("sbom_source"),
        "raw_vulnerability_count": threat_intel.get(
            "raw_vulnerability_count", 0
        ),
        "vulnerability_count": threat_intel.get("vulnerability_count", 0),
        "priority_summary": result.metadata.get("policy", {}).get("summary", {}),
        "findings": threat_intel.get("vulnerabilities", []),
        "remediation_plan": result.metadata.get("remediation_plan", []),
        "validation": result.metadata.get("validation", {}),
    }
