
# Findings and Severity

- **Critical:** credible directly exploitable condition with severe impact and meaningful exposure.
- **High:** serious weakness materially increasing compromise likelihood or impact.
- **Medium:** relevant weakness requiring remediation planning.
- **Low:** limited risk or defense-in-depth gap.
- **Info:** contextual observation or hardening opportunity.

Confidence: high (unambiguous), medium (strong indicator with benign alternatives), low (heuristic/incomplete).

Status: `observed`, `needs_review`, `confirmed`, `not_applicable`.

Severity is contextual. A localhost-only listener is not equivalent to a publicly exposed service. A package version alone does not prove vulnerability; verify vendor advisories and backports. Findings must state observation, evidence, impact, limitations and practical next steps.
