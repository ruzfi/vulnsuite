## What and why

<!-- What this changes and why. Link the issue it closes. -->
Closes #

## Checklist

- [ ] Branched from `dev` and targeting `dev` (see CONTRIBUTING.md — `main` is release-only).
- [ ] `make test` and `make lint` (gofmt + go vet) pass.
- [ ] Added or updated tests for the change.
- [ ] If the contract changed (`pkg/contract`): updated `schemas/contract.schema.json` and `docs/CONTRACT.md`, and every template in vulnsuite-templates still loads (`vulnsuite validate`).
- [ ] One logical change per PR.
