# Unsupported ecosystem demo

This repository intentionally contains no `package.json`. The current SAVEMit prototype supports Node/npm only, so Repository Scanner must stop safely before SBOM generation, remediation planning, Docker validation, or a pull request.

Expected outcome: a clear message explaining that Node/npm support is required. This demonstrates a safe refusal, rather than attempting an unsafe or invented patch.
