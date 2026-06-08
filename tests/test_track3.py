"""
Unit tests for Track 3 (volume/noise handling):
  orchestrator/baseliner.py, orchestrator/risk_scorer.py, blue_agent/env_whitelist.py

Run:  python tests/test_track3.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orchestrator.baseliner import EntityBaseliner
from orchestrator.risk_scorer import RiskScorer
from blue_agent.env_whitelist import EnvironmentWhitelist


# ── baseliner ───────────────────────────────────────────────────────────────────
def test_baseline_beats_fixed_threshold():
    """Same value (8 failures) is a spray on a quiet host, normal on a busy one —
    a thing a fixed `>= 12` threshold cannot express (it would MISS the quiet spray)."""
    b = EntityBaseliner().fit({
        "quiet_host": [2, 3, 1, 2, 2, 3, 2, 1, 2, 2, 3, 2],
        "busy_host":  [40, 38, 42, 45, 39, 41, 43, 44, 38, 40, 42, 41],
    })
    # high-side anomaly = spray (signed modified-z above cutoff)
    assert b.modified_z("quiet_host", 8) > b.cutoff, b.modified_z("quiet_host", 8)
    assert not (b.modified_z("busy_host", 8) > b.cutoff), b.modified_z("busy_host", 8)
    print("PASS test_baseline_beats_fixed_threshold: quiet z=%.1f busy z=%.1f"
          % (b.modified_z("quiet_host", 8), b.modified_z("busy_host", 8)))


def test_mad_robust_to_training_outlier():
    """A prior attack spike (100) in the training window must NOT corrupt the
    baseline. MAD ignores it; mean/stdev would be poisoned and miss the next spike."""
    training = [3, 5, 4, 6, 5, 7, 4, 6, 100, 5, 3, 6]   # one poison sample
    b = EntityBaseliner().fit({"h": training})
    assert b.is_anomalous("h", 30), "MAD-based baseline must still catch a 30 spike"
    # show the naive mean/stdev z would have MISSED it
    import statistics
    naive_z = (30 - statistics.fmean(training)) / statistics.pstdev(training)
    assert naive_z < 3.5, f"naive z={naive_z:.2f} would miss — that's the point"
    print("PASS test_mad_robust_to_training_outlier: MAD caught 30, naive z=%.2f missed" % naive_z)


def test_global_fallback_for_unseen_entity():
    b = EntityBaseliner(min_observations=5).fit({
        "a": [2, 2, 3, 2, 2, 3], "b": [3, 2, 2, 3, 2, 2],
    })
    # brand-new entity -> judged against the pooled global baseline, not auto-ignored
    assert b.is_anomalous("never_seen_host", 40)
    print("PASS test_global_fallback_for_unseen_entity")


def test_baseliner_to_spl():
    spl = EntityBaseliner().to_spl(index="arena_attacks", metric_field="failures",
                                   entity_field="Account_Name")
    assert "eventstats" in spl and "zscore" in spl and "Account_Name" in spl
    print("PASS test_baseliner_to_spl")


# ── risk scorer ───────────────────────────────────────────────────────────────
def test_single_low_signal_not_notable():
    r = RiskScorer(notable_threshold=80)
    r.add_risk("host1", 20, "brute_force", now=1000)
    assert not r.is_notable("host1", now=1000)
    print("PASS test_single_low_signal_not_notable")


def test_killchain_accumulates_to_notable():
    """Low-confidence signals across the kill chain on ONE host sum to a notable."""
    r = RiskScorer(notable_threshold=80)
    for score, tech, src in [(20, "T1110.001", "brute"), (25, "T1136.001", "new_acct"),
                             (20, "T1053.005", "schtask"), (30, "T1003.001", "lsass")]:
        r.add_risk("host1", score, src, technique=tech, now=1000)
    assert r.is_notable("host1", now=1000)
    notable = r.to_notable("host1", now=1000)
    assert notable["total_risk"] == 95
    assert len(notable["techniques"]) == 4
    print("PASS test_killchain_accumulates_to_notable:", notable["total_risk"], notable["techniques"])


def test_poison_flood_resisted():
    """50 low-severity false positives (Red's alert-fatigue play) never cross the
    notable threshold — RBA is the production counter to poisoning."""
    r = RiskScorer(notable_threshold=80)
    for i in range(50):
        r.add_risk("host1", 1.0, "noisy_rule", message="benign FP", now=1000)
    assert not r.is_notable("host1", now=1000), r.total_risk("host1", now=1000)
    print("PASS test_poison_flood_resisted: 50 FPs -> risk %.0f < 80" % r.total_risk("host1", now=1000))


def test_risk_decays_out_of_window():
    r = RiskScorer(notable_threshold=80, window_seconds=3600)
    r.add_risk("host1", 100, "old_spike", now=1000)
    assert r.is_notable("host1", now=1000)
    # an hour and a second later, the old risk has aged out
    assert not r.is_notable("host1", now=1000 + 3601)
    print("PASS test_risk_decays_out_of_window")


def test_risk_to_spl():
    spl = RiskScorer().to_spl(risk_index="risk")
    assert "sum(risk_score)" in spl and "risk_object" in spl
    print("PASS test_risk_to_spl")


# ── env whitelist ─────────────────────────────────────────────────────────────
def _benign_logons(account, n):
    return [{"sourcetype": "WinEventLog:Security", "EventCode": 4624,
             "Account_Name": account, "Logon_Type": 3} for _ in range(n)]


def test_whitelist_learns_service_account():
    wl = EnvironmentWhitelist(min_count=3).learn(_benign_logons("svc_backup", 5))
    benign = {"sourcetype": "WinEventLog:Security", "EventCode": 4624, "Account_Name": "svc_backup"}
    attacker = {"sourcetype": "WinEventLog:Security", "EventCode": 4625, "Account_Name": "attacker1"}
    assert wl.is_whitelisted(benign)
    assert not wl.is_whitelisted(attacker)
    print("PASS test_whitelist_learns_service_account")


def test_whitelist_per_signal_isolation():
    """A trusted logon account is NOT trusted for a different signal (LSASS access)."""
    wl = EnvironmentWhitelist(min_count=3).learn(_benign_logons("svc_backup", 5))
    lsass = {"sourcetype": "Sysmon", "EventCode": 10, "Account_Name": "svc_backup"}
    assert not wl.is_whitelisted(lsass), "trust must not transfer across signal types"
    print("PASS test_whitelist_per_signal_isolation")


def test_whitelist_filter_and_spl():
    wl = EnvironmentWhitelist(min_count=3).learn(_benign_logons("svc_backup", 5))
    events = _benign_logons("svc_backup", 2) + [
        {"sourcetype": "WinEventLog:Security", "EventCode": 4625, "Account_Name": "attacker1"}]
    survivors = wl.filter(events)
    assert all(e["Account_Name"] == "attacker1" for e in survivors), survivors
    spl = wl.to_spl_filter()
    assert spl.startswith("NOT (") and "svc_backup" in spl
    print("PASS test_whitelist_filter_and_spl:", spl)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"FAIL {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
