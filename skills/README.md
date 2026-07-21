# Project Formalization Skills

The repository ships two complementary Codex skills:

- [`project-formalization`](project-formalization/): C-focused, formal-methods
  workflow. It requires a machine-checked formal backend and treats sanitizer
  replays as corroborating production evidence.
- [`project-formalization-raw`](project-formalization-raw/): general-purpose
  vulnerability-experiment harness. It supports formal methods when useful but
  does not require C or a formal backend.

Each skill is self-contained with its templates, references, harness scripts,
and tests. The generic private-workspace rules within these skills are runtime
instructions for future experiments; the public repository contains no such
workspace or artifact.
