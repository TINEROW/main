## Description
<!-- Provide a concise summary of the changes made in this PR -->

Closes #<!-- Replace with issue number, e.g. Closes #409 -->

## Type of Change
- [ ] `feat`: New feature
- [ ] `fix`: Bug fix
- [ ] `docs`: Documentation update
- [ ] `refactor`: Code refactoring
- [ ] `test`: Test suite update
- [ ] `chore`: Maintenance / CI / tooling

## Workspaces Impacted
- [ ] Frontend (`frontend/`)
- [ ] Backend (`backend/`)
- [ ] Soroban Smart Contracts (`contracts/`)
- [ ] Noir ZK Circuits (`zk/`)
- [ ] CLI (`cli/`)
- [ ] DevX / Tooling / Docs (`.github/`, `devx/`, `docs/`)

---

## Change-Impact Labels

The CI labeler applies `impact/*` labels automatically based on file paths.
For each label that fires **or** that you believe applies, confirm the
corresponding gate below.  Check **N/A** when the label genuinely does not
apply to this PR.

> **Privacy rule:** Do not paste real video hashes, witness values, nullifier
> values, credential secrets, or private keys into this template.

### `impact/protocol`
Changes the `hpx-vi/1` verifier-input codec, nullifier derivation, public-input
layout, or cross-layer conformance vectors.

- [ ] Conformance vectors regenerated (`python zk/vectors/generate_vectors.py`)
      and `zk/vectors/verifier_conformance_v1.json` updated.
- [ ] `release/compatibility-manifest.json` version fields bumped.
- [ ] Migration note added to `MIGRATION_GUIDE.md`.
- [ ] Threat-model cross-reference: <!-- section in THREAT_MODEL.md -->
- [ ] N/A — this PR does not touch the `hpx-vi/1` protocol layer.

### `impact/privacy`
Touches a boundary where witness values, credential secrets, or nullifiers could
be logged, echoed, or transmitted.

- [ ] Negative test added that asserts the relevant response/log never contains
      a secret field (witness, nullifier, credentialSecret, privateKey).
- [ ] `devx/e2e_env_matrix.py` adversarial profile exercises the changed path.
- [ ] N/A — no new logging, response serialisation, or error-message paths.

### `impact/security`
Modifies authentication, authorisation, key handling, ZK circuit constraints,
Soroban access-control, CSP headers, or secret-scanning configuration.

- [ ] Security notes documented below (or in a linked issue/doc).
- [ ] THREAT_MODEL.md updated or a rationale given for why it need not change.
- [ ] N/A — no auth, key-handling, or access-control paths changed.

### `impact/deployment`
Affects Docker images, compose files, hosting configs, nginx CSP, SBOM, or the
GitHub release workflow.

- [ ] `DEPLOY.md` updated with any new environment variables or steps.
- [ ] Rollback procedure described below or in `docs/release-operations.md`.
- [ ] N/A — no deployment artefacts or release workflow changed.

### `impact/contract`
Modifies Soroban registry logic, event schema, verifier binding, issuer registry,
nullifier store, or delegation rules.

- [ ] `contract_interface_version` bumped in `release/compatibility-manifest.json`.
- [ ] Migration path described in `MIGRATION_GUIDE.md`.
- [ ] `release/verifier-binding.json` updated if verifier WASM hash changed.
- [ ] N/A — no Soroban contract logic or interface changed.

### `impact/zk-circuit`
Changes Noir circuit source, toolchain lock, artifact manifest, or conformance
vectors.

- [ ] Toolchain versions updated in `zk/toolchain.lock.json` if nargo/bb changed.
- [ ] Reproducible build verified (`zk/noir/scripts/reproducible-build.sh`).
- [ ] Browser artifact manifest updated (`zk/browser.artifacts.manifest.json`).
- [ ] N/A — no Noir circuit source or toolchain changed.

### `impact/api`
Adds, removes, or changes a backend route, request/response schema, cursor
pagination contract, or steganography header set.

- [ ] Backward compatibility confirmed for stored evidence callers (or breaking
      change documented with migration note).
- [ ] OpenAPI schema regenerated (`python devx/generate_api_schema.py`).
- [ ] N/A — no backend routes or schema fields changed.

### `impact/cli`
Changes the CLI command surface, receipt format, manifest codec, or Stellar
lookup output.

- [ ] `cli/README.md` updated.
- [ ] `release/compatibility-manifest.json` CLI version bumped.
- [ ] N/A — no CLI command surface or output format changed.

---

## Checklist & Verification

- [ ] All build, lint, and test commands pass locally for affected workspaces.
- [ ] Commit messages follow the Conventional Commits format.
- [ ] No real video files, credential secrets, witness values, or private keys
      are included in this PR.
- [ ] **Screenshots:** (Required if UI/Frontend changed) Attached below or N/A.
- [ ] **Security Notes:** (Required if auth, contracts, keys, or ZK circuits
      changed) Detailed below or N/A.

### Screenshots (if applicable)
<!-- Attach screenshots or GIFs showing UI changes -->

### Security Notes (if applicable)
<!-- Explain security considerations, cryptographic assumptions, or contract
     state impacts.  Reference the relevant THREAT_MODEL.md section. -->

### Rollback / Migration Notes (if applicable)
<!-- Describe how to roll back this change and whether stored evidence or
     on-chain state requires a migration step. -->

### Test Evidence
```text
Paste terminal output showing passing test results for all affected workspaces.
```
