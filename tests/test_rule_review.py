"""
Unit tests for Track 2 (human-in-the-loop review gate):
  rule_review/queue.py       — ReviewQueue + compute_confidence
  rule_review/dry_runner.py  — DryRunner (blast-radius / FP estimate)
  rule_review/explainer.py   — explain() + recommendation()
  rule_review/deployer.py    — GitDeployer (commit approved rule to git store)

Pure stdlib + git. The Flask UI (server.py) is exercised only if Flask is installed;
otherwise that one test is skipped. Run:  python tests/test_rule_review.py
"""
import os
import shutil
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rule_review.queue import ReviewQueue, PendingRule, compute_confidence
from rule_review.dry_runner import DryRunner
from rule_review.explainer import explain, recommendation
from rule_review.deployer import GitDeployer


# ── confidence scoring ────────────────────────────────────────────────────────
def test_confidence_rewards_specific_anchored_rule():
    """Sigma + a real field anchor + clean dry-run → high confidence (deploy-worthy)."""
    spl = 'index=arena_attacks EventCode=4625 Sub_Status="0xC000006A" | stats count by src_ip'
    score = compute_confidence(
        spl=spl, sigma="title: failed logon spray\ndetection: {}",
        sample_events=[{}, {}, {}], dry_run={"fp_rate": 0.0, "total_hits": 7},
    )
    assert score >= 0.9, score
    print("PASS test_confidence_rewards_specific_anchored_rule:", score)


def test_confidence_penalizes_volume_only_rule():
    """A bare count threshold (only `index=` plumbing, no field anchor) with a noisy
    dry-run is the exact rule Red wants Blue to ship — confidence must crater."""
    spl = "index=arena_attacks | stats count by src_ip | where count > 100"
    score = compute_confidence(
        spl=spl, sigma="", sample_events=[{}],
        dry_run={"fp_rate": 0.5, "total_hits": 200},
    )
    assert score < 0.45, score
    print("PASS test_confidence_penalizes_volume_only_rule:", score)


def test_confidence_count_only_penalty_actually_fires():
    """Regression guard: `index=...` must NOT count as a specific anchor, or the
    count-only penalty becomes dead code. Same rule, with vs. without a field anchor."""
    base_dr = {"fp_rate": None, "total_hits": 5}
    volume_only = compute_confidence(
        "index=x | stats count by h | where count > 50", "", [], base_dr)
    anchored = compute_confidence(
        'index=x Account_Name="bob" | stats count by h | where count > 50', "", [], base_dr)
    assert anchored > volume_only, (anchored, volume_only)
    print("PASS test_confidence_count_only_penalty_actually_fires: anchored=%.2f volume=%.2f"
          % (anchored, volume_only))


# ── queue: persistence + decision lifecycle ───────────────────────────────────
def _sample_rule(**kw) -> PendingRule:
    base = dict(
        technique="T1110.001", rule_name="generated_r1_T1110_001",
        spl='index=arena_attacks EventCode=4625 | stats count by src_ip',
        sigma="title: spray\ndetection: {}", sample_events=[{}, {}, {}],
        confidence=0.82, dry_run={"total_hits": 9, "fp_estimate": 0, "fp_rate": 0.0, "window": "-24h..now"},
    )
    base.update(kw)
    return PendingRule(**base)


def test_queue_enqueue_and_persist_roundtrip():
    tmp = tempfile.mkdtemp()
    try:
        path = os.path.join(tmp, "queue.json")
        q1 = ReviewQueue(path=path)
        rid = q1.enqueue(_sample_rule())
        # A brand-new queue reading the same file must see the rule (survives restart).
        q2 = ReviewQueue(path=path)
        r = q2.get(rid)
        assert r is not None and r.technique == "T1110.001"
        assert q2.list(status="pending") and len(q2.list()) == 1
        print("PASS test_queue_enqueue_and_persist_roundtrip:", rid)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_queue_approve_reject_lifecycle():
    tmp = tempfile.mkdtemp()
    try:
        q = ReviewQueue(path=os.path.join(tmp, "q.json"))
        a = q.enqueue(_sample_rule(rule_name="ruleA"))
        b = q.enqueue(_sample_rule(rule_name="ruleB"))
        assert q.approve(a, reviewer="jacob", notes="looks good").status == "approved"
        assert q.reject(b, reviewer="jacob").status == "rejected"
        # A decided rule cannot be re-decided (gate is one-way).
        assert q.approve(b) is None, "rejected rule must not be re-approvable"
        assert q.counts().get("approved") == 1 and q.counts().get("rejected") == 1
        print("PASS test_queue_approve_reject_lifecycle:", q.counts())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ── dry runner ────────────────────────────────────────────────────────────────
class _FakeSearch:
    """Satisfies the run_search(spl, earliest, latest) duck-type the DryRunner needs."""
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def run_search(self, spl, earliest="-24h", latest="now"):
        self.calls.append((spl, earliest, latest))
        return list(self.rows)


class _BoomSearch:
    def run_search(self, spl, earliest="-24h", latest="now"):
        raise RuntimeError("splunk unreachable")


def test_dry_runner_counts_labelled_false_positives():
    """In the arena, Red's noise is tagged arena_technique='benign' — count FPs exactly."""
    rows = [
        {"src_ip": "10.0.0.5", "arena_technique": "T1110.001"},   # true positive
        {"src_ip": "10.0.0.9", "arena_technique": "benign"},      # labelled FP
        {"src_ip": "10.0.0.9", "arena_technique": "benign"},      # labelled FP
    ]
    out = DryRunner(_FakeSearch(rows)).run("index=x ...")
    assert out["total_hits"] == 3 and out["fp_estimate"] == 2
    assert out["fp_rate"] == round(2 / 3, 3), out
    print("PASS test_dry_runner_counts_labelled_false_positives:", out)


def test_dry_runner_blast_radius_on_clean_window():
    """estimate_false_positives: every hit in a believed-clean window is a suspected FP."""
    dr = DryRunner(_FakeSearch([{"a": 1}, {"a": 2}]))
    out = dr.estimate_false_positives("index=x ...", "-7d@d", "-1d@d")
    assert out["suspected_fp"] == 2 and "window" in out
    print("PASS test_dry_runner_blast_radius_on_clean_window:", out)


def test_dry_runner_never_crashes_review_flow():
    """A Splunk outage must degrade to an error dict, not raise into the reviewer."""
    out = DryRunner(_BoomSearch()).run("index=x ...")
    assert out["total_hits"] is None and "error" in out
    print("PASS test_dry_runner_never_crashes_review_flow:", out["error"][:40])


# ── explainer ─────────────────────────────────────────────────────────────────
def test_explain_translates_spl_to_english():
    r = _sample_rule(
        spl='index=arena_attacks EventCode=4625 Sub_Status="0xC000006A" '
            '| stats count by src_ip | where count > 5',
        confidence=0.81,
        dry_run={"total_hits": 9, "fp_estimate": 0, "fp_rate": 0.0, "window": "-24h..now"},
    )
    text = explain(r)
    assert "failed logon" in text                 # 4625 decoded to security meaning
    assert "Sub_Status" in text                   # field anchor surfaced
    assert "count" in text and "5" in text        # threshold surfaced
    assert "safe to deploy" in text               # confidence verdict
    print("PASS test_explain_translates_spl_to_english")


def test_explain_flags_volume_only_rule():
    r = _sample_rule(spl="index=arena_attacks | stats count by src_ip | where count > 100",
                     sigma="", confidence=0.3,
                     dry_run={"total_hits": 300, "fp_estimate": 120, "fp_rate": 0.4, "window": "-24h..now"})
    text = explain(r)
    assert "volume-only" in text and "false positive" in text
    print("PASS test_explain_flags_volume_only_rule")


def test_recommendation_thresholds():
    approve = _sample_rule(confidence=0.85, dry_run={"fp_rate": 0.05})
    reject = _sample_rule(confidence=0.30, dry_run={"fp_rate": 0.6})
    review = _sample_rule(confidence=0.55, dry_run={"fp_rate": 0.2})
    assert recommendation(approve) == "APPROVE"
    assert recommendation(reject) == "REJECT"
    assert recommendation(review) == "REVIEW"
    print("PASS test_recommendation_thresholds")


# ── git deployer ──────────────────────────────────────────────────────────────
def _rmtree_writable(path):
    """Windows leaves git objects read-only; chmod then retry on rmtree."""
    def onerror(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    shutil.rmtree(path, onerror=onerror)


def _init_repo():
    tmp = tempfile.mkdtemp()
    env = {**os.environ}
    subprocess.run(["git", "init", "-q"], cwd=tmp, check=True, env=env)
    subprocess.run(["git", "config", "user.email", "ci@purpleforge.test"], cwd=tmp, check=True)
    subprocess.run(["git", "config", "user.name", "PurpleForge CI"], cwd=tmp, check=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=tmp, check=True)
    return tmp


def test_deployer_commits_only_the_rule_files():
    if not shutil.which("git"):
        print("SKIP test_deployer_commits_only_the_rule_files: git not on PATH")
        return
    tmp = _init_repo()
    try:
        # An unrelated, untracked file in the tree — deploy must NOT sweep it in.
        with open(os.path.join(tmp, "secret.env"), "w") as f:
            f.write("API_KEY=do-not-commit\n")

        dep = GitDeployer(repo_root=tmp)
        rule = _sample_rule(rule_name="generated_r2_T1110_001",
                            spl='index=arena_attacks EventCode=4625 Sub_Status="0xC000006A"')
        res = dep.deploy(rule, reviewer="jacob")

        assert res["committed"] is True, res
        assert res["commit_sha"], res
        # The .spl and .yml landed in the store with the exact reviewed content.
        spl_on_disk = os.path.join(tmp, "blue_agent", "rules", "generated", "generated_r2_T1110_001.spl")
        assert os.path.exists(spl_on_disk)
        assert 'Sub_Status="0xC000006A"' in open(spl_on_disk).read()

        # The commit contains ONLY the rule files — never `git add -A` of the whole tree.
        files = subprocess.run(
            ["git", "show", "--name-only", "--pretty=format:", "HEAD"],
            cwd=tmp, capture_output=True, text=True).stdout.split()
        assert any(p.endswith("generated_r2_T1110_001.spl") for p in files), files
        assert any(p.endswith("generated_r2_T1110_001.yml") for p in files), files
        assert not any("secret.env" in p for p in files), f"deploy leaked unrelated file: {files}"

        # And secret.env is still untracked afterward.
        status = subprocess.run(["git", "status", "--porcelain"], cwd=tmp,
                                capture_output=True, text=True).stdout
        assert "?? secret.env" in status, status
        print("PASS test_deployer_commits_only_the_rule_files:", res["commit_sha"][:10])
    finally:
        _rmtree_writable(tmp)


def test_deployer_idempotent_no_change():
    if not shutil.which("git"):
        print("SKIP test_deployer_idempotent_no_change: git not on PATH")
        return
    tmp = _init_repo()
    try:
        dep = GitDeployer(repo_root=tmp)
        rule = _sample_rule(rule_name="generated_r3_T1003_001")
        first = dep.deploy(rule)
        assert first["committed"] is True
        # Deploying byte-identical content again must NOT create an empty commit.
        second = dep.deploy(rule)
        assert second["committed"] is False and second.get("reason") == "no_changes", second
        print("PASS test_deployer_idempotent_no_change:", second.get("reason"))
    finally:
        _rmtree_writable(tmp)


def test_deployer_rejects_non_git_dir():
    tmp = tempfile.mkdtemp()
    try:
        res = GitDeployer(repo_root=tmp).deploy(_sample_rule())
        assert res["committed"] is False and "not a git repository" in res["error"]
        print("PASS test_deployer_rejects_non_git_dir")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ── optional Flask UI (skipped if Flask absent) ───────────────────────────────
def test_server_approve_flow_if_flask_present():
    try:
        import flask  # noqa: F401
    except ImportError:
        print("SKIP test_server_approve_flow_if_flask_present: Flask not installed")
        return
    if not shutil.which("git"):
        print("SKIP test_server_approve_flow_if_flask_present: git not on PATH")
        return
    from rule_review.server import create_app
    tmp = _init_repo()
    try:
        q = ReviewQueue(path=os.path.join(tmp, "queue.json"))
        rid = q.enqueue(_sample_rule(rule_name="generated_r4_T1053_005"))
        app = create_app(queue=q, deployer=GitDeployer(repo_root=tmp))
        client = app.test_client()
        assert b"Rule Review Queue" in client.get("/").data
        resp = client.post(f"/rule/{rid}/approve", data={"reviewer": "analyst"})
        assert resp.status_code == 200 and b"Deployed" in resp.data
        assert q.get(rid).status == "deployed"
        print("PASS test_server_approve_flow_if_flask_present")
    finally:
        _rmtree_writable(tmp)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"FAIL {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001 - surface unexpected errors per-test
            failed += 1
            print(f"ERROR {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
