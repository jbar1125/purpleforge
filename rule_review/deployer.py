"""
rule_review/deployer.py — commit an APPROVED rule to the rule store (detection-as-code).

The whole point of the review gate is that nothing reaches production until a human
approves it. This module is the "production" step: once approved, the rule's SPL (and
its portable Sigma source, if present) is written into blue_agent/rules/generated/ and
committed to git. Git is the rule store — every deployed detection has an author, a
timestamp, a reviewer, and a diff. That's the audit trail a real SOC needs.

Design notes
------------
* repo_root and rules_subdir are injectable so this is unit-testable against a throwaway
  `git init` repo (the tests do exactly that).
* We `git add` ONLY the specific files we wrote — never `git add -A`/`git add .` — so a
  deploy can never sweep up unrelated working-tree changes (secrets, configs, scratch).
* We never bypass hooks. If a pre-commit hook rejects the rule, that's a real signal and
  the deploy fails loudly rather than being forced through.
* Every git failure is caught and returned as {committed: False, error: ...}; a deploy
  must never raise into the review UI / CLI.
"""
from __future__ import annotations

import subprocess
from pathlib import Path


class GitDeployer:
    """
    Commit approved rules to the git-backed rule store.

    Args:
        repo_root:    the git repository root (defaults to the project root, three levels
                      up from this file: rule_review/ -> purpleforge/ -> repo).
        rules_subdir: where deployed rules land, relative to repo_root.
        git_timeout:  seconds before a git subprocess is abandoned.
    """

    def __init__(
        self,
        repo_root: str | Path | None = None,
        rules_subdir: str = "blue_agent/rules/generated",
        git_timeout: float = 30.0,
    ):
        # rule_review/deployer.py -> purpleforge/ is the project root the agents share.
        default_root = Path(__file__).resolve().parent.parent
        self.repo_root = Path(repo_root).resolve() if repo_root else default_root
        self.rules_dir = self.repo_root / rules_subdir
        self.git_timeout = git_timeout

    # ── git plumbing ────────────────────────────────────────────────────────────
    def _git(self, *args: str) -> tuple[int, str, str]:
        """Run a git command in the repo root. Returns (returncode, stdout, stderr)."""
        proc = subprocess.run(
            ["git", *args],
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
            timeout=self.git_timeout,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()

    def is_git_repo(self) -> bool:
        try:
            code, out, _ = self._git("rev-parse", "--is-inside-work-tree")
        except (FileNotFoundError, subprocess.SubprocessError):
            return False
        return code == 0 and out == "true"

    # ── deploy ──────────────────────────────────────────────────────────────────
    def deploy(self, rule, reviewer: str | None = None) -> dict:
        """
        Write `rule`'s SPL (+ Sigma) into the rule store and commit it.

        `rule` is any object exposing .rule_name/.spl and optionally
        .sigma/.technique/.confidence/.dry_run/.reviewer/.id (a PendingRule satisfies
        this). Returns a result dict — never raises:

            {committed, commit_sha, paths, message, error?, reason?}

        committed is False (with a `reason`/`error`) when there's nothing new to commit,
        the tree isn't a git repo, or git itself fails.
        """
        rule_name = getattr(rule, "rule_name", None) or getattr(rule, "id", "rule")
        spl = (getattr(rule, "spl", "") or "").rstrip() + "\n"
        sigma = getattr(rule, "sigma", "") or ""
        reviewer = reviewer or getattr(rule, "reviewer", "") or "analyst"

        if not spl.strip():
            return {"committed": False, "paths": [], "error": "rule has empty SPL"}
        if not self.is_git_repo():
            return {"committed": False, "paths": [],
                    "error": f"{self.repo_root} is not a git repository"}

        # 1. Write the rule files into the store.
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        written: list[Path] = []
        spl_path = self.rules_dir / f"{rule_name}.spl"
        spl_path.write_text(spl, encoding="utf-8")
        written.append(spl_path)
        if sigma.strip():
            yml_path = self.rules_dir / f"{rule_name}.yml"
            yml_path.write_text(sigma.rstrip() + "\n", encoding="utf-8")
            written.append(yml_path)

        rel_paths = [str(p.relative_to(self.repo_root)) for p in written]

        # 2. Stage ONLY the files we wrote (never `git add -A`).
        code, _, err = self._git("add", "--", *[str(p) for p in written])
        if code != 0:
            return {"committed": False, "paths": rel_paths, "error": f"git add failed: {err}"}

        # 3. Nothing staged means the deployed content matches what's already committed.
        code, staged, _ = self._git("diff", "--cached", "--name-only", "--", *[str(p) for p in written])
        if code == 0 and not staged:
            return {"committed": False, "paths": rel_paths, "reason": "no_changes",
                    "error": "rule already deployed (no content change)"}

        # 4. Commit just those paths with a provenance-rich message.
        message = self._commit_message(rule, reviewer, rel_paths)
        code, _, err = self._git("commit", "-m", message, "--", *[str(p) for p in written])
        if code != 0:
            return {"committed": False, "paths": rel_paths, "error": f"git commit failed: {err}"}

        _, sha, _ = self._git("rev-parse", "HEAD")
        return {"committed": True, "commit_sha": sha, "paths": rel_paths, "message": message}

    # ── commit message ──────────────────────────────────────────────────────────
    @staticmethod
    def _commit_message(rule, reviewer: str, rel_paths: list[str]) -> str:
        technique = getattr(rule, "technique", "") or "?"
        rule_name = getattr(rule, "rule_name", "") or "rule"
        conf = getattr(rule, "confidence", None)
        dr = getattr(rule, "dry_run", {}) or {}
        rid = getattr(rule, "id", "")

        subject = f"detect: deploy reviewed rule {rule_name} ({technique})"
        body = ["", "Approved via human-in-the-loop review gate.", f"Reviewer: {reviewer}"]
        if conf is not None:
            body.append(f"Confidence: {conf}")
        if dr.get("total_hits") is not None:
            body.append(
                f"Dry-run: {dr.get('total_hits')} hit(s), "
                f"{dr.get('fp_estimate', 0)} suspected FP "
                f"(rate {dr.get('fp_rate', 0)}, window {dr.get('window', 'n/a')})"
            )
        if rid:
            body.append(f"Review-ID: {rid}")
        body.append("Files: " + ", ".join(rel_paths))
        return subject + "\n" + "\n".join(body)
