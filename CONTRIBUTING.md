# Contributing to jolarca-dr

This repository holds the disaster recovery, backup and business continuity
documentation for the `jolarca-dev` marketplace. It is in scope for SOC 2 Type II,
ISO 27001:2022, PCI-DSS 4.0 and GDPR, so changes are treated as controlled
records rather than as ordinary documentation edits. An auditor will read the
history of this repository to decide whether recovery capability was actually
maintained.

Read [README.md](README.md) for what is here, and [SECURITY.md](SECURITY.md)
before reporting anything security related. Licensing is proprietary; see
[LICENSE](LICENSE).

## Change control

Every change follows the same path. There is no exception for small edits,
because the audit trail does not distinguish between small and large.

1. Create a feature branch from `main`. Never commit or push directly to `main`.
2. Make one logical change per pull request.
3. Confirm the required status check passes locally before pushing.
4. Open a pull request with a description that says what changed and why.
5. Merge by squash once checks are green, then delete the branch.

The default branch is protected by the `protect-main` ruleset, which blocks
branch deletion, blocks force pushes and non-fast-forward updates, and requires a
linear history. It declares no bypass actors, so these rules apply to
administrators as well. If a rule genuinely has to be set aside, that is an
out-of-band change: record it, and restore the rule immediately afterwards.

Merge settings are squash-only. Merge commits and rebase merges are disabled,
and branches are deleted on merge. This is deliberate: a linear history where
each commit maps to one reviewed change is what makes the record auditable.

## Commit requirements

Sign every commit with a GPG key registered on your GitHub account:

```bash
git commit -S -m "docs: clarify RTO for the payment datastore"
```

Server-side signature enforcement is off because provider automation commits
cannot be signed. Signing is therefore a contributor obligation, and it is the
compensating control for the approval deviation described below. Unsigned human
commits should be treated as a finding.

Use Conventional Commits for the subject line. The types that appear here are
`docs`, `feat`, `fix` and `chore`.

Commits made through the GitHub web interface require DCO sign-off, which the
organisation enforces at the organisation level.

## Review

The organisation currently has one member, and GitHub does not permit approving
your own pull request. The required approving review count is therefore `0`,
recorded as a dated solo-era deviation with signed commits as the compensating
control. This is a tracked risk acceptance, not an absence of review.

Self-review is still mandatory. Before requesting merge, confirm:

- the description explains the change and links any related issue or rehearsal;
- the required `lint` check is green;
- no unrelated files are included;
- no unresolved review threads remain.

When a second operator joins, raise the required approving review count to `1`
and enable code owner review. Do not enable code owner review before then: with a
single code owner it would deadlock every pull request.

## Required status checks

| Check | Emits | What it verifies |
| --- | --- | --- |
| `lint` | `.github/workflows/ci.yml` | Document structure, relative links, governance file presence, CODEOWNERS validity |
| `gitleaks` | `.github/workflows/ci.yml` | No credential-shaped strings in the diff or in history |

Run the lint locally before pushing:

```bash
python3 scripts/lint_docs.py
```

## What must never be committed

- Credentials, keys, tokens, certificates, or any secret value of any kind.
  Secret scanning and push protection are enabled on this repository, and a
  push containing a recognised secret will be rejected. Do not work around that
  rejection; remove the secret and rotate it.
- Personal data, including customer records, staff details and anything that
  identifies a natural person. Rehearsal evidence must use synthetic data.
- Terraform state files, or any `*.tfstate` variant. State can contain secrets
  in plaintext.
- The contents of `.env` files, `secrets.json` or `credentials.json`.

`.gitignore` blocks these patterns. A file that is ignored is still a file that
exists on your machine: keep real values in a local, untracked variables file
rather than pasting them into a document and relying on the ignore rule.

## A note on infrastructure identifiers

This repository is public. Runbooks name real buckets, projects, service accounts
and secret-store paths, because a runbook that cannot be executed literally is
not a runbook and will fail during the incident it exists for. That is a
deliberate trade-off, and it is under review: whether these literals should be
parameterised into an untracked variables file is an open owner decision.

Until it is settled, treat every identifier here as already public. Never add a
new one without asking whether the runbook can reference it indirectly, and never
add a credential value on the assumption that the identifier is already exposed.

## Rehearsals and evidence

Changes to runbooks should be exercised, not just reviewed. If a change alters a
recovery step, record the outcome in `rehearsals/evidence/` using the template
there. A runbook that has never been executed is an untested hypothesis about
recovery.

## Reporting problems

Security vulnerabilities go through the private disclosure path in
[SECURITY.md](SECURITY.md). Do not open a public issue for them.

For anything else, open an issue describing what you expected, what happened,
and which document or runbook is affected.
