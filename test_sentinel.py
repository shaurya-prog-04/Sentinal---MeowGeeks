"""Tests for Sentinel.  Run:  pytest

- Most tests need NO database (they use InMemoryRecorder).
- Database tests use an in-memory SQLite database by default, so they run anywhere.
  Set SENTINEL_TEST_DB_URL to a MySQL URL to run them against MySQL instead
  (use a separate test database: the tests DELETE all tables in it).
"""
import os
import threading

import pytest

import sentinel as s


# ── helpers ───────────────────────────────────────────────────────────────────

def run_mode(key, mode, limits=None):
    rec = s.InMemoryRecorder(f"mem-{mode}")
    s.run_execution(s.SCENARIOS[key], mode, limits or s.Limits(), rec)
    return rec.events


def report_for(key, limits=None):
    limits = limits or s.Limits()
    evs = {m: run_mode(key, m, limits) for m in s.MODES}
    return s.build_report(s.SCENARIOS[key], limits, evs, {m: "completed" for m in s.MODES})


def symlinks_supported(tmp_path):
    try:
        os.symlink(tmp_path, tmp_path / "probe_link", target_is_directory=True)
        return True
    except (OSError, NotImplementedError):
        return False


# ── 1. config ─────────────────────────────────────────────────────────────────

def test_placeholder_password_rejected(monkeypatch):
    monkeypatch.setenv("SENTINEL_DB_URL", "mysql+pymysql://u:CHANGE_ME@127.0.0.1/sentinel")
    with pytest.raises(s.ConfigError):
        s.load_settings()


def test_wrong_driver_rejected(monkeypatch):
    monkeypatch.setenv("SENTINEL_DB_URL", "sqlite:///x.db")
    with pytest.raises(s.ConfigError):
        s.load_settings()


def test_valid_url_accepted(monkeypatch):
    url = "mysql+pymysql://u:secret@127.0.0.1:3306/sentinel"
    monkeypatch.setenv("SENTINEL_DB_URL", url)
    assert s.load_settings().db_url == url


def test_limits_validation():
    with pytest.raises(ValueError):
        s.Limits(budget=0).validate()
    with pytest.raises(ValueError):
        s.Limits(budget=60, outer_ceiling=50).validate()
    assert s.Limits().validate().budget == 5


# ── 2. contracts / adapter output ─────────────────────────────────────────────

@pytest.mark.parametrize("raw", [
    None, "text", {"output": 1}, {"output": "x", "actions": "nope"},
    {"output": "x", "actions": [{"kind": "rm_rf"}]},
    {"output": "x", "actions": [{"kind": "read_file"}]},
    {"output": "x", "actions": [{"kind": "op", "cost_ms": -1}]},
])
def test_malformed_adapter_output_rejected(raw):
    with pytest.raises(s.AdapterError):
        s.parse_model_response(raw)


def test_mock_is_identical_in_both_modes():
    """The mock is never told the mode, so its proposals cannot differ."""
    m = s.MockModel()
    ctx = {"secret": s.CANARY_A, "sandbox_root": "/x", "budget": 5, "deadline_ms": 1000,
           "user_task": "", "document": ""}
    for sc in s.SCENARIOS.values():
        for c in sc.cases:
            assert m.propose(c.script, dict(ctx)) == m.propose(c.script, dict(ctx))


def test_events_never_store_the_raw_secret():
    for key in s.SCENARIOS:
        for mode in s.MODES:
            for e in run_mode(key, mode):
                blob = s.canonical_json(e.details)
                assert s.CANARY_A not in blob and s.CANARY_B not in blob, (key, mode, e.type)


# ── 3. path policy (protected) ────────────────────────────────────────────────

@pytest.fixture
def ws(tmp_path):
    root = tmp_path / "box"
    (root / "workspace" / "data").mkdir(parents=True)
    (root / "workspace" / "notes.txt").write_text("ok")
    (root / "workspace" / "data" / "r.csv").write_text("a,b")
    (root / "restricted").mkdir()
    (root / "restricted" / "creds.txt").write_text("secret")
    (root / "workspace_evil").mkdir()
    (root / "workspace_evil" / "x").write_text("evil")
    return root / "workspace"


@pytest.mark.parametrize("path", ["notes.txt", "data/../notes.txt", "data/r.csv", "./notes.txt",
                                  "data\\r.csv"])
def test_paths_inside_workspace_allowed(ws, path):
    d, resolved = s.check_workspace_path(ws, path)
    assert d.allow, d
    assert resolved is not None


@pytest.mark.parametrize("path,rule", [
    ("../restricted/creds.txt", "WS_OUTSIDE_ROOT"),
    ("..\\restricted\\creds.txt", "WS_OUTSIDE_ROOT"),
    ("../workspace_evil/x", "WS_OUTSIDE_ROOT"),
    ("../../../../../../etc/hosts", "WS_OUTSIDE_ROOT"),
    ("", "WS_INVALID_PATH"),
    ("a\x00b", "WS_INVALID_PATH"),
    ("a" * 2000, "WS_INVALID_PATH"),
    ("\\\\server\\share\\f", "WS_UNC_PATH"),
    ("//server/share/f", "WS_UNC_PATH"),
    ("C:\\Windows\\win.ini", "WS_DRIVE_PATH"),
    ("notes.txt:hidden", "WS_ADS_PATH"),
    ("CON", "WS_RESERVED_NAME"),
    ("data/nul.txt", "WS_RESERVED_NAME"),
    ("missing.txt", "WS_NOT_FOUND"),
    ("data", "WS_NOT_A_FILE"),
])
def test_bad_paths_denied(ws, path, rule):
    d, resolved = s.check_workspace_path(ws, path)
    assert not d.allow
    assert d.rule_id == rule
    assert resolved is None
    assert str(ws) not in d.reason  # denial never leaks host paths


def test_absolute_path_outside_denied(ws):
    d, _ = s.check_workspace_path(ws, str(ws.parent / "restricted" / "creds.txt"))
    assert not d.allow


def test_symlink_escape_denied(ws, tmp_path):
    if not symlinks_supported(tmp_path):
        pytest.skip("symlinks not permitted here (Windows without Developer Mode) — NOT a pass")
    os.symlink(ws.parent / "restricted", ws / "esc", target_is_directory=True)
    d, _ = s.check_workspace_path(ws, "esc/creds.txt")
    assert not d.allow and d.rule_id == "WS_OUTSIDE_ROOT"


def test_internal_symlink_allowed(ws, tmp_path):
    if not symlinks_supported(tmp_path):
        pytest.skip("symlinks not permitted here — NOT a pass")
    os.symlink("data/r.csv", ws / "lnk")
    d, _ = s.check_workspace_path(ws, "lnk")
    assert d.allow


def test_is_within_is_component_wise(tmp_path):
    assert not s.is_within(tmp_path / "workspace_evil", tmp_path / "workspace")
    assert s.is_within(tmp_path / "workspace" / "a", tmp_path / "workspace")


# ── 4. scenarios: every case matches its declared expectation (golden test) ───

@pytest.mark.parametrize("key", list(s.SCENARIOS))
def test_scenario_outcomes_match_expectations(key, tmp_path):
    content = report_for(key)
    sym = symlinks_supported(tmp_path)
    for c in content["cases"]:
        case = s.SCENARIOS[key].case(c["case_key"])
        if case.needs and not sym:
            assert c["results"]["protected"]["outcome"] == "inconclusive"  # skipped != passed
            continue
        for mode in s.MODES:
            got = c["results"][mode]["outcome"]
            assert got == c["expected"][mode], f"{c['case_key']} {mode}: got {got}"


def test_c_a1_baseline_is_success_bounded_by_outer_ceiling():   # rule (c)
    r = {c["case_key"]: c for c in report_for("C")["cases"]}["C-A1"]["results"]["baseline"]
    assert r["outcome"] == "attack_succeeded"
    assert r["qualifier"] == "bounded_by_outer_ceiling"
    assert r["ops_attempted"] == s.Limits().outer_ceiling + 1


def test_b_i1_baseline_inconclusive_outer_containment():
    r = {c["case_key"]: c for c in report_for("B")["cases"]}["B-I1"]
    assert r["results"]["baseline"]["inconclusive_reason"] == "outer_containment"
    assert r["results"]["protected"]["outcome"] == "attack_prevented"


def test_budget_boundary_exact_n_is_allowed():
    for n in (1, 3, 5, 7):
        r = {c["case_key"]: c for c in report_for("C", s.Limits(budget=n))["cases"]}
        assert r["C-B2"]["results"]["protected"]["outcome"] == "benign_completed", n
        assert r["C-A1"]["results"]["protected"]["ops_permitted"] == n


def test_simulated_timeout_is_labelled_simulated():
    evs = run_mode("C", "protected")
    t = [e for e in evs if e.type == "timeout_triggered"]
    assert t and all(e.details["simulated"] for e in t)
    done = [e for e in evs if e.type == "case_completed" and e.case_key == "C-A3"]
    assert done[0].details["termination_reason"] == "simulated_timeout"


def test_cancellation_token_stops_cases():
    cancel = threading.Event()
    cancel.set()
    rec = s.InMemoryRecorder()
    s.run_execution(s.SCENARIO_C, "protected", s.Limits(), rec, cancel=cancel)
    reasons = {e.details["termination_reason"] for e in rec.events if e.type == "case_completed"}
    assert reasons == {"cancelled"}


def test_detection_is_informational_only():
    evs = run_mode("A", "baseline")
    assert any(e.type == "suspicious_content_detected" for e in evs)
    r = {c["case_key"]: c for c in report_for("A")["cases"]}
    assert r["A-B2"]["results"]["protected"]["outcome"] == "benign_completed"


def test_sandbox_is_removed_after_run():
    rec = s.InMemoryRecorder()
    s.run_execution(s.SCENARIO_B, "baseline", s.Limits(), rec)
    # the sandbox root is the parent of any read path; just check temp dirs are gone
    import glob, tempfile
    assert not glob.glob(os.path.join(tempfile.gettempdir(), "sentinel_*", "workspace"))


# ── 5. metrics (known answers) ────────────────────────────────────────────────

def _o(kind, outcome, objectives=None):
    return {"kind": kind, "outcome": outcome, "objectives": objectives or {}}


def test_metrics_known_answers():
    outcomes = {
        "baseline": {"x1": _o("attack", "attack_succeeded"), "x2": _o("attack", "attack_succeeded"),
                     "x3": _o("attack", "attack_succeeded"), "x4": _o("attack", "inconclusive"),
                     "b1": _o("benign", "benign_completed"), "b2": _o("benign", "benign_completed")},
        "protected": {"x1": _o("attack", "attack_prevented"), "x2": _o("attack", "attack_succeeded"),
                      "x3": _o("attack", "inconclusive"), "x4": _o("attack", "attack_prevented"),
                      "b1": _o("benign", "benign_completed"), "b2": _o("benign", "benign_blocked")},
    }
    m = {(x["key"], x["scope"]): x for x in s.compute_metrics(outcomes, s.SCENARIO_C)}
    assert (m["attack_success_rate", "baseline"]["numerator"], m["attack_success_rate", "baseline"]["denominator"]) == (3, 3)
    assert (m["attack_success_rate", "protected"]["numerator"], m["attack_success_rate", "protected"]["denominator"]) == (1, 3)
    assert (m["prevention_rate", "protected"]["numerator"], m["prevention_rate", "protected"]["denominator"]) == (2, 3)
    # rule (b): x3 is inconclusive in protected -> excluded from the paired denominator
    br = m["baseline_resolved_prevention_rate", "paired"]
    assert (br["numerator"], br["denominator"]) == (1, 2)
    assert m["excluded_pairs_protected_inconclusive", "paired"]["numerator"] == 1
    assert (m["false_positive_rate", "protected"]["numerator"], m["false_positive_rate", "protected"]["denominator"]) == (1, 2)


def test_zero_denominator_is_unavailable():
    m = s.compute_metrics({"baseline": {}, "protected": {}}, s.SCENARIO_C)
    assert all(x["status"] == "unavailable" and x["value"] is None for x in m)


def test_report_hash_is_reproducible_from_same_events():
    evs = {m: run_mode("B", m) for m in s.MODES}
    st = {m: "completed" for m in s.MODES}
    a = s.build_report(s.SCENARIO_B, s.Limits(), evs, st)
    b = s.build_report(s.SCENARIO_B, s.Limits(), evs, st)
    assert s.report_sha256(a) == s.report_sha256(b)


def test_two_runs_give_same_outcomes():
    def outcomes(c):
        return [(x["case_key"], x["results"]["baseline"]["outcome"], x["results"]["protected"]["outcome"])
                for x in c["cases"]]
    for key in s.SCENARIOS:
        assert outcomes(report_for(key)) == outcomes(report_for(key))


def test_partial_execution_marks_report_partial():
    evs = {m: run_mode("C", m) for m in s.MODES}
    evs["protected"] = [e for e in evs["protected"] if e.case_key in (None, "C-B1")]
    c = s.build_report(s.SCENARIO_C, s.Limits(), evs, {"baseline": "completed", "protected": "failed"})
    assert c["validity"] == "partial"
    r = {x["case_key"]: x for x in c["cases"]}
    assert r["C-A1"]["results"]["protected"]["inconclusive_reason"] == "not_executed"


# ── 6. database (SQLite by default; MySQL if SENTINEL_TEST_DB_URL is set) ─────

@pytest.fixture
def engine():
    url = os.getenv("SENTINEL_TEST_DB_URL", "sqlite://")
    eng = s.make_engine(url)
    s.reset_db(eng)
    yield eng
    s.metadata.drop_all(eng)
    eng.dispose()


def test_full_run_stores_events_and_report(engine):
    run_id = s.start_comparison_run(engine, "B")
    v = s.get_run_view(engine, run_id)
    assert v["run"]["status"] == "completed"
    assert {e["status"] for e in v["executions"]} == {"completed"}
    assert v["report"]["validity"] in ("valid", "flagged")
    for ex in v["executions"]:  # every event belongs to this run's executions, seq 1..n
        evs = v["events"][ex["mode"]]
        assert [e["seq"] for e in evs] == list(range(1, len(evs) + 1))
        assert all(e["execution_id"] == ex["id"] for e in evs)


def test_events_do_not_cross_between_runs(engine):
    r1 = s.start_comparison_run(engine, "C")
    r2 = s.start_comparison_run(engine, "C")
    ids1 = {e["id"] for e in s.get_run_view(engine, r1)["executions"]}
    for evs in s.get_run_view(engine, r2)["events"].values():
        assert not any(e["execution_id"] in ids1 for e in evs)


def test_regenerated_report_has_identical_hash(engine):
    run_id = s.start_comparison_run(engine, "A")
    res = s.regenerate_report(engine, run_id)
    assert res["identical"], res


def test_same_request_token_does_not_duplicate(engine):
    a = s.start_comparison_run(engine, "C", request_token="tok-1")
    b = s.start_comparison_run(engine, "C", request_token="tok-1")
    assert a == b
    assert len(s.list_runs(engine)) == 1


def test_illegal_transition_raises(engine):
    run_id = s.start_comparison_run(engine, "C")
    with engine.begin() as conn:
        with pytest.raises(s.IllegalTransition):
            s.transition(conn, s.t_run, run_id, "completed", "running")
    with engine.begin() as conn:
        with pytest.raises(s.IllegalTransition):  # wrong expected status -> 0 rows -> error
            s.transition(conn, s.t_run, run_id, "running", "evaluating")


def test_stale_runs_become_abandoned(engine):
    from datetime import timedelta
    run_id = s.start_comparison_run(engine, "C")
    with engine.begin() as conn:
        conn.execute(s.update(s.t_run).where(s.t_run.c.id == run_id).values(
            status="running", started_at=s.utcnow() - timedelta(hours=2)))
    assert s.cleanup_stale_runs(engine) == 1
    assert s.get_run_view(engine, run_id)["run"]["status"] == "abandoned"


def test_scenario_sync_refuses_changed_definition_without_version_bump(engine):
    s.sync_scenarios(engine)
    with engine.begin() as conn:
        conn.execute(s.update(s.t_scenario).where(s.t_scenario.c.scenario_key == "A")
                     .values(definition_sha256="0" * 64))
    with pytest.raises(RuntimeError, match="Bump the version"):
        s.sync_scenarios(engine, ["A"])


def test_inconclusive_requires_reason_in_db(engine):
    run_id = s.start_comparison_run(engine, "A")
    with engine.connect() as conn:
        rows = conn.execute(s.select(s.t_case_outcome).where(s.t_case_outcome.c.outcome == "inconclusive")).mappings().all()
    assert rows and all(r["inconclusive_reason"] for r in rows)
