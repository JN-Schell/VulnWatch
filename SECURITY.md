# Security reporting

Do not publish passwords, tokens, real scanner data, or exploit details affecting deployed organizations in a public issue. If the GitHub repository has private vulnerability reporting enabled, use **Security → Report a vulnerability**. Otherwise contact the repository owner privately before disclosure; no monitored security email or response SLA is claimed.

Include affected version/commit, minimal defensive reproduction, expected/actual behavior and impact. Use synthetic assets and data. Do not scan or attack deployments without explicit authorization.

This repository is an MIT-licensed portfolio application, not a security certification or a managed production service. Review `docs/security.md` and `docs/threat-model.md` before deployment. Development mode, synthetic seed data and test credentials must never be exposed as a production installation.
