import httpx

from app.agents.base_agent import BaseAgent


class ThreatIntelAgent(BaseAgent):
    OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
    OSV_VULNERABILITY_URL = "https://api.osv.dev/v1/vulns/{}"
    BATCH_SIZE = 100

    def _query_batch(self, client, queries):
        try:
            response = client.post(self.OSV_BATCH_URL, json={"queries": queries})
            response.raise_for_status()
        except httpx.HTTPError as error:
            raise RuntimeError(f"OSV vulnerability lookup failed: {error}") from error

        results = response.json().get("results")
        if not isinstance(results, list) or len(results) != len(queries):
            raise RuntimeError("OSV returned an unexpected batch response.")

        return results

    def _fetch_vulnerability_details(self, client, vulnerability_ids):
        details = {}

        for vulnerability_id in vulnerability_ids:
            try:
                response = client.get(
                    self.OSV_VULNERABILITY_URL.format(vulnerability_id)
                )
                response.raise_for_status()
                details[vulnerability_id] = response.json()
            except (httpx.HTTPError, ValueError) as error:
                raise RuntimeError(
                    f"Unable to retrieve OSV advisory {vulnerability_id}: {error}"
                ) from error

        return details

    @staticmethod
    def _deduplication_key(advisory):
        aliases = advisory.get("aliases", [])
        return next(
            (alias for alias in aliases if alias.startswith("CVE-")),
            advisory["id"],
        )

    def _build_clean_findings(self, raw_findings, advisory_details):
        grouped_findings = {}

        for raw_finding in raw_findings:
            advisory = advisory_details[raw_finding["vulnerability_id"]]
            deduplication_key = self._deduplication_key(advisory)
            finding = grouped_findings.setdefault(
                deduplication_key,
                {
                    "id": deduplication_key,
                    "aliases": advisory.get("aliases", []),
                    "summary": advisory.get("summary", "No summary available"),
                    "severity": advisory.get("severity", []),
                    "advisory_ids": [],
                    "affected_packages": [],
                    "fixed_versions": [],
                },
            )

            if raw_finding["vulnerability_id"] not in finding["advisory_ids"]:
                finding["advisory_ids"].append(raw_finding["vulnerability_id"])

            package = {
                "package": raw_finding["package"],
                "version": raw_finding["version"],
                "purl": raw_finding["purl"],
            }
            if package not in finding["affected_packages"]:
                finding["affected_packages"].append(package)

            package_name = package["package"].lower()
            for affected in advisory.get("affected", []):
                advisory_package = affected.get("package", {}).get("name", "").lower()
                if advisory_package != package_name:
                    continue
                for affected_range in affected.get("ranges", []):
                    for event in affected_range.get("events", []):
                        fixed_version = event.get("fixed")
                        if fixed_version and fixed_version not in finding["fixed_versions"]:
                            finding["fixed_versions"].append(fixed_version)

        return list(grouped_findings.values())

    def execute(self, case):
        print("Threat Intelligence")

        sbom = case.metadata.get("sbom")
        if not sbom:
            raise ValueError("Threat Intelligence requires an SBOM.")

        components = sbom.get("components", [])
        query_components = []
        queries = []

        for component in components:
            purl = component.get("purl")
            if not purl or "@" not in purl:
                continue

            query_components.append(component)
            queries.append({"package": {"purl": purl}})

        raw_findings = []
        with httpx.Client(timeout=30.0) as client:
            for start in range(0, len(queries), self.BATCH_SIZE):
                query_batch = queries[start:start + self.BATCH_SIZE]
                component_batch = query_components[start:start + self.BATCH_SIZE]
                results = self._query_batch(client, query_batch)

                for component, result in zip(component_batch, results):
                    for vulnerability in result.get("vulns", []):
                        raw_findings.append({
                            "package": component.get("name", "Unknown package"),
                            "version": component.get("version", "Unknown version"),
                            "purl": component["purl"],
                            "vulnerability_id": vulnerability["id"],
                            "modified": vulnerability.get("modified"),
                        })

            advisory_details = self._fetch_vulnerability_details(
                client,
                {finding["vulnerability_id"] for finding in raw_findings},
            )

        findings = self._build_clean_findings(raw_findings, advisory_details)
        case.findings.extend(findings)
        case.metadata["threat_intel"] = {
            "packages_queried": len(queries),
            "raw_findings": raw_findings,
            "raw_vulnerability_count": len(raw_findings),
            "vulnerabilities": findings,
            "vulnerability_count": len(findings),
        }
        case.stage = "Threat Intelligence"

        case.history.append({
            "agent": "Threat Intelligence",
            "stage": case.stage,
            "status": "Completed",
            "packages_queried": len(queries),
            "raw_vulnerability_count": len(raw_findings),
            "vulnerability_count": len(findings),
        })

        return case
