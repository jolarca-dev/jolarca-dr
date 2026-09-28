#!/usr/bin/env python3
"""Structural lint for the jolarca-dr document set.

Produces the `lint` status context declared in jolarca-control
`repos/jolarca-dr.yml#branch_protection.main.required_status_checks.contexts`.
Before this file existed that context was declared but nothing emitted it, so
the gate it was meant to drive could never be satisfied — the D-22/D-27 failure
class: a control present in configuration that never fires.

Deliberately dependency-free (Python standard library only). A documentation
repository in PCI-DSS scope should not pull an unpinned markdown linter and its
transitive tree from a registry on every push just to check that a file ends
with a newline.

RULES, and why each is here
---------------------------
Every rule below was probed against the live document set on 2026-09-28 and
passed with zero violations before it was enabled. A lint gate that fails on
arrival trains operators to ignore it, which is worse than no gate.

Rules intentionally NOT enforced:

* "No TODO/TBD placeholders". `policies/business-continuity-policy.md` leaves
  the backup operator, security lead and communications lead roles as `TBD`,
  and `metrics/dr-metrics.md` leaves two success rates unmeasured. Those are an
  honest record of a single-operator organisation (jolarca-dev has one seat).
  Blocking on them would invite the author to invent a name — a false entry in a
  document an auditor will rely on during an incident — or to delete the row and
  hide the gap. The staffing gap belongs in the risk register as a dated
  deviation alongside D-04 and D-10, not in a linter.

* "No cloud resource identifiers". Runbooks legitimately name buckets, projects
  and service accounts so they can be executed under stress. Whether those
  literals should be parameterised into a gitignored variables file is an open
  owner decision (the repository is public), not something a linter may settle
  silently.

* "No absolute filesystem paths". An earlier revision of this rule rejected
  `/opt/*` outright and immediately failed on `runbooks/state-restore.md`,
  `runbooks/infrastructure-restore.md` and `metrics/dr-metrics.md` — all of which
  name `/opt/jolarca/backups/tfstate/` because that IS the off-host Terraform
  state backup location the runbook exists to restore from (D-02). A runbook
  that cannot name its own restore path is not a runbook. The rule is therefore
  narrowed to user home directories, which is where a pasted workstation path
  actually comes from. The disclosure question — publishing the off-host backup
  path in a PUBLIC repository tells an attacker where state files live — is real,
  but it belongs to the same open owner decision as the cloud identifiers above,
  not to a linter.

Exit 0 when clean, 1 when any rule is violated. Run: python3 scripts/lint_docs.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Governance files every repository in the fleet must carry. CONTRIBUTING.md and
# LICENSE may otherwise be inherited from jolarca-dev/.github, but inheritance is
# invisible in this repository and unverifiable from a checkout — so they are
# required explicitly here (audit findings F-09 and F-10).
REQUIRED_FILES = (
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "LICENSE",
    ".gitignore",
    ".github/CODEOWNERS",
)

# ADR-0004 R4: marketplace repositories must never reference mission-platform
# principals. Fleet-wide this was already violated once (D-20), which left
# require_code_owner_reviews enabled but unsatisfiable on five repositories.
FORBIDDEN_CODEOWNER_REFS = ("@jol-infrastructure/", "@journeyoflife-org/", "@jol-")

CONFLICT_MARKER_RE = re.compile(r"^(?:<{7}|={7}|>{7})(?:\s|$)", re.MULTILINE)
RELATIVE_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
EXTERNAL_PREFIXES = ("http://", "https://", "mailto:", "#")

# Developer home directories must not be published: they disclose the operator's
# account name and machine layout, and they are wrong for every other reader.
# Deliberately excludes operational roots such as /opt/jolarca/backups/, which
# the restore runbooks must name — see the docstring.
LOCAL_PATH_RE = re.compile(r"/(?:home|Users)/[A-Za-z0-9._-]+/")


def markdown_files() -> list[Path]:
    """Every tracked Markdown document, excluding VCS and tool state."""
    skip = {".git", ".idea", ".venv", "node_modules", ".qoder", ".claude"}
    return sorted(
        p
        for p in ROOT.rglob("*.md")
        if not (set(p.relative_to(ROOT).parts[:-1]) & skip)
    )


def check_structure(path: Path, text: str) -> list[str]:
    errors: list[str] = []
    if not text.endswith("\n"):
        errors.append(f"{path}: file does not end with a newline")
    elif text.endswith("\n\n"):
        errors.append(f"{path}: file ends with a blank line")
    if "\t" in text:
        errors.append(f"{path}: contains a tab character")
    for number, line in enumerate(text.split("\n"), start=1):
        if line != line.rstrip():
            errors.append(f"{path}:{number}: trailing whitespace")
            break
    body = [line for line in text.split("\n") if line.strip()]
    if not body:
        errors.append(f"{path}: file is empty")
    elif not body[0].startswith("# "):
        errors.append(f"{path}: first heading is not a level-1 heading")
    if CONFLICT_MARKER_RE.search(text):
        errors.append(f"{path}: unresolved merge conflict marker")
    return errors


def check_links(path: Path, text: str) -> list[str]:
    """Relative links must resolve. A runbook that links to a file nobody can
    open is a runbook that fails during the incident it exists for."""
    errors: list[str] = []
    for match in RELATIVE_LINK_RE.finditer(text):
        target = match.group(1).split("#", 1)[0].strip()
        if not target or target.startswith(EXTERNAL_PREFIXES):
            continue
        if target.startswith(("gs://", "s3://", "vault/")):
            continue  # resource URIs, not document links
        if not (path.parent / target).resolve().exists():
            errors.append(f"{path}: relative link does not resolve: {target}")
    return errors


def check_local_paths(path: Path, text: str) -> list[str]:
    errors = []
    for match in LOCAL_PATH_RE.finditer(text):
        errors.append(f"{path}: developer home-directory path: {match.group(0)}")
        break
    return errors


def check_required_files() -> list[str]:
    return [f"missing required file: {name}" for name in REQUIRED_FILES if not (ROOT / name).exists()]


def check_codeowners() -> list[str]:
    path = ROOT / ".github" / "CODEOWNERS"
    if not path.exists():
        return []  # already reported by check_required_files
    errors: list[str] = []
    owners: list[str] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").split("\n"), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for ref in stripped.split()[1:]:
            owners.append(ref)
            if ref.startswith(FORBIDDEN_CODEOWNER_REFS):
                errors.append(f".github/CODEOWNERS:{number}: mission-platform reference {ref} (ADR-0004 R4)")
    if not owners:
        errors.append(".github/CODEOWNERS declares no owners — code-owner review would be inert (D-20)")
    return errors


def main() -> int:
    errors: list[str] = []
    documents = markdown_files()
    for path in documents:
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT)
        errors += check_structure(relative, text)
        errors += check_links(relative, text)
        errors += check_local_paths(relative, text)
    errors += check_required_files()
    errors += check_codeowners()

    print(f"lint_docs: scanned {len(documents)} Markdown file(s) under {ROOT.name}/")
    if errors:
        print(f"FAIL — {len(errors)} violation(s):", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print("PASS — structure, links, governance files and CODEOWNERS are clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
