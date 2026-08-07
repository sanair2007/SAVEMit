import re
from pathlib import Path

from app.agents.base_agent import BaseAgent


class ReachabilityAgent(BaseAgent):
    SOURCE_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
    EXCLUDED_DIRECTORIES = {
        ".git",
        "node_modules",
        ".next",
        "build",
        "coverage",
        "dist",
    }
    IMPORT_PATTERN = re.compile(
        r"(?:import\s+(?:[\w*${},\s]+\s+from\s+)?|require\s*\(|import\s*\()"
        r"[\"'](?P<module>[^\"']+)[\"']"
    )

    @staticmethod
    def _package_name_from_purl(purl):
        package = purl.removeprefix("pkg:npm/").split("@", 1)[0]
        if package.startswith("%40"):
            package = "@" + package[3:]
        return package

    @staticmethod
    def _import_package_name(module_name):
        if module_name.startswith((".", "/")):
            return None
        if module_name.startswith("@"):
            return "/".join(module_name.split("/", 2)[:2])
        return module_name.split("/", 1)[0]

    def _find_imports(self, repository_path):
        imports = {}
        for source_file in Path(repository_path).rglob("*"):
            if (
                not source_file.is_file()
                or source_file.suffix not in self.SOURCE_EXTENSIONS
                or any(part in self.EXCLUDED_DIRECTORIES for part in source_file.parts)
            ):
                continue

            try:
                content = source_file.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            for match in self.IMPORT_PATTERN.finditer(content):
                module_name = match.group("module")
                package_name = self._import_package_name(module_name)
                if not package_name:
                    continue

                imports.setdefault(package_name, []).append({
                    "file": str(source_file.relative_to(repository_path)),
                    "import": match.group(0),
                })

        return imports

    def execute(self, case):
        print("Reachability Analysis")

        repository_path = case.metadata.get("repository_path")
        if not repository_path:
            raise ValueError("Reachability Analysis requires a repository path.")

        imports = self._find_imports(repository_path)
        transitive_dependencies = case.metadata.get("demo", {}).get("transitive_dependencies", {})
        reachable_count = 0
        for finding in case.findings:
            evidence = []
            dependency_context = "DIRECT"
            for package in finding["affected_packages"]:
                package_name = self._package_name_from_purl(package["purl"])
                if package_name in transitive_dependencies:
                    dependency_context = "TRANSITIVE"
                    continue
                evidence.extend(imports.get(package_name, []))

            reachable = bool(evidence)
            finding["reachability"] = {
                "reachable": reachable,
                "evidence": evidence,
                "dependency_context": dependency_context,
            }
            reachable_count += reachable

        summary = {
            "reachable": reachable_count,
            "not_reachable": len(case.findings) - reachable_count,
        }
        case.metadata["reachability"] = {"summary": summary}
        case.stage = "Reachability Analysis"
        case.history.append({
            "agent": "Reachability Agent",
            "stage": case.stage,
            "status": "Completed",
            "reachability_summary": summary,
        })
        return case
