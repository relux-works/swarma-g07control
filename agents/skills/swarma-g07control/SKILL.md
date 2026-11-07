---
name: swarma-g07control
description: Use Swarma G07 control's Linux Go admission API, custodian-pinned prerequisites, one-slot receipts and typed refusals. Use for this module's control boundary or synthetic validation, not grant issuance, token acquisition or Host activation.
---

# Swarma G07 control

This module admits keeper control consumption before runtime entry. It does not
invoke Host. Import `github.com/relux-works/swarma-g07control`; there is no CLI.

Read [the API and custody reference](references/control.md) for `Open(policyFD)`,
`Consume(ctx, eventID, tokenFD)`, descriptor ownership, prerequisites, receipt
interpretation and refusal handling. The implemented definitions are in
[types.go](../../../types.go), [auth.go](../../../auth.go) and
[store_linux.go](../../../store_linux.go). Read the [module README](../../../README.md)
for the frozen boundary and outstanding live-adoption requirements.

Use only a separately admitted custodian policy and existing anchored store.
Caller-created policy or synthetic positive custody fixtures do not establish
source admission, exclusive execution custody or permission to operate. Missing
prerequisites stop the workflow; there is no initialization or compatibility
fallback in this API.

Only `NEWLY_CONSUMED` can be considered by the actual custodian for one later
inspect-then-invoke action under the existing authority. `INSPECTION_ONLY` never
reissues authority. Preserve every existing claim after failure or expiry; do not
delete, repair, reset or invent a new retry slot. Control consumption neither
starts T0 nor extends the 1260-second whole-runtime budget. The custodian still
checks `issued <= T0 < latest` immediately before the frozen first runtime effect.

For offline validation, use the reference's existing synthetic test commands
only inside the required isolated harness. Passing tests does not qualify a
live Matrix origin, storage durability, installation or runtime activation.
