"""Sentinel — Streamlit UI.   Run:  streamlit run app.py

Rules followed here:
- The database is the source of truth; session_state only holds UI state.
- Untrusted fixture/document text is shown with st.text / st.code, never st.markdown.
- Every result is labelled SIMULATED.
"""
import json
import uuid

import pandas as pd
import streamlit as st

import sentinel as s

st.set_page_config(page_title="Sentinel", layout="wide")


@st.cache_resource
def engine():
    return s.get_engine()


def content_of(rep):
    c = rep["content"]
    return c if isinstance(c, dict) else json.loads(c)


def outcome_cell(r):
    txt = r["outcome"]
    if r.get("inconclusive_reason"):
        txt += f" ({r['inconclusive_reason']})"
    if r.get("qualifier"):
        txt += f" [{r['qualifier']}]"
    return txt


def summary_line(c):
    """One sentence: what baseline let through and what protected mode did about it."""
    attacks = [x["results"] for x in c["cases"] if x["kind"] == "attack"]
    benign = [x["results"] for x in c["cases"] if x["kind"] == "benign"]

    def n(results, mode, outcome):
        return sum(r[mode]["outcome"] == outcome for r in results)

    fp = n(benign, "protected", "benign_blocked")
    line = (f"Baseline: {n(attacks, 'baseline', 'attack_succeeded')} attacks succeeded → "
            f"Protected: {n(attacks, 'protected', 'attack_prevented')} prevented, "
            f"{n(attacks, 'protected', 'attack_succeeded')} still vulnerable, "
            f"{fp} false positive{'' if fp == 1 else 's'}")
    inconclusive = n(attacks + benign, "protected", "inconclusive")
    if inconclusive:
        line += f", {inconclusive} inconclusive"
    return line + "."


# ── pages ────────────────────────────────────────────────────────────────────
def page_health():
    st.header("System health")
    st.success(f"MySQL {info['version']} connected (database: {info['database']})")
    st.write(f"App version {s.APP_VERSION}, evaluator v{s.EVALUATOR_VERSION}")
    st.write("real_timeout: **not implemented** (simulated deadline only)")


def page_scenarios():
    st.header("Scenarios")
    for sc in s.SCENARIOS.values():
        with st.expander(f"{sc.key} — {sc.title} ({len(sc.cases)} cases)"):
            st.write(sc.description)
            st.write(f"**Threat:** {sc.threat_summary}")
            st.write("**Limitations (what this does not demonstrate):**")
            for lim in sc.limitations:
                st.write(f"- {lim}")
            st.dataframe(pd.DataFrame([{
                "case": c.case_key, "kind": c.kind, "title": c.title,
                "expected baseline": c.expected["baseline"], "expected protected": c.expected["protected"],
                "expected safe behaviour": c.expected_safe_behavior} for c in sc.cases]),
                hide_index=True, use_container_width=True)
            docs = [c for c in sc.cases if c.document]
            if docs:
                st.write("**Untrusted documents (shown as plain text):**")
                for c in docs:
                    st.code(c.document, language=None)


def page_new_comparison():
    st.header("Run a baseline vs protected comparison")
    if "request_token" not in st.session_state:
        st.session_state.request_token = str(uuid.uuid4())
    with st.form("new_run"):
        key = st.selectbox("Scenario", list(s.SCENARIOS),
                           format_func=lambda k: f"{k} — {s.SCENARIOS[k].title}")
        c1, c2, c3 = st.columns(3)
        budget = c1.number_input("Operation budget (protected)", 1, 49, s.Limits.budget)
        deadline = c2.number_input("Simulated deadline ms (protected)", 100, 60000, s.Limits.deadline_ms, step=100)
        ceiling = c3.number_input("Outer ceiling (both modes)", 10, 500, s.Limits.outer_ceiling)
        go = st.form_submit_button("Run comparison")
    if go:
        try:
            limits = s.Limits(budget=int(budget), deadline_ms=int(deadline),
                              outer_ceiling=int(ceiling)).validate()
        except ValueError as exc:
            st.error(str(exc))
            return
        with st.spinner("Running baseline, then protected..."):
            run_id = s.start_comparison_run(eng, key, limits,
                                            request_token=st.session_state.request_token)
        st.session_state.request_token = str(uuid.uuid4())  # next submit is a new run
        report = s.get_run_view(eng, run_id)["report"]
        # kept in session_state so the message and its button survive the rerun the click causes
        st.session_state.last_run = {
            "run_id": run_id, "scenario": f"{key} — {s.SCENARIOS[key].title}",
            "summary": summary_line(content_of(report)) if report else "No report was produced."}

    last = st.session_state.get("last_run")
    if last:
        st.success(f"**Scenario {last['scenario']}: comparison finished.**  \n{last['summary']}")
        if st.button("Open results report →", type="primary"):
            st.session_state.open_run = last["run_id"]
            st.switch_page(RESULTS)


def page_results():
    st.header("Results")
    runs = s.list_runs(eng)
    if not runs:
        st.info("No runs yet. Start one on the New comparison page.")
        return
    ids = [r["id"] for r in runs]
    default = st.session_state.pop("open_run", None) or st.query_params.get("run", ids[0])
    run_id = st.selectbox("Run", ids, index=ids.index(default) if default in ids else 0,
                          format_func=lambda i: next(f"{r['created_at']} · {r['scenario_key']} · {r['status']}"
                                                     for r in runs if r["id"] == i))
    st.query_params["run"] = run_id
    view = s.get_run_view(eng, run_id)
    st.write(f"Status: **{view['run']['status']}**")
    if not view["report"]:
        st.warning("No report for this run.")
        return
    c = content_of(view["report"])
    if c["label"] != s.SIMULATED_LABEL:  # the standard label is already shown under the top bar
        st.caption(c["label"])
    st.write(f"Validity: **{c['validity']}** · Flags: {', '.join(c['flags']) or 'none'} · "
             f"Report hash `{view['report']['content_sha256'][:16]}…`")

    tab_cmp, tab_metrics, tab_timeline, tab_report = st.tabs(
        ["Comparison", "Metrics", "Event timeline", "Report"])

    with tab_cmp:
        rows = []
        for case in c["cases"]:
            b, p = case["results"]["baseline"], case["results"]["protected"]
            change = ("improved" if b["outcome"] == "attack_succeeded" and p["outcome"] == "attack_prevented"
                      else "false positive" if p["outcome"] == "benign_blocked"
                      else "still vulnerable" if p["outcome"] == "attack_succeeded"
                      else "inconclusive" if "inconclusive" in (b["outcome"], p["outcome"]) else "same")
            rows.append({"case": case["case_key"], "kind": case["kind"], "title": case["title"],
                         "baseline": outcome_cell(b), "protected": outcome_cell(p), "change": change,
                         "matches expectation": all(case["matches_expectation"].values())})
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
        pick = st.selectbox("Case detail", [r["case"] for r in rows])
        case = next(x for x in c["cases"] if x["case_key"] == pick)
        col1, col2 = st.columns(2)
        for col, mode in ((col1, "baseline"), (col2, "protected")):
            r = case["results"][mode]
            col.subheader(mode)
            col.write(f"Outcome: **{outcome_cell(r)}**")
            col.text(r["explanation"])
            col.write(f"Ops attempted/permitted/denied: {r['ops_attempted']}/{r['ops_permitted']}/{r['ops_denied']}")
            if r["objectives"]:
                col.json(r["objectives"])

    with tab_metrics:
        st.caption("Inconclusive cases are excluded from every denominator and counted separately.")
        st.dataframe(pd.DataFrame([{"metric": m["key"], "scope": m["scope"],
                                    "value": s.fmt_ratio(m["numerator"], m["denominator"])}
                                   for m in c["metrics"]]), hide_index=True, use_container_width=True)

    with tab_timeline:
        mode = st.radio("Mode", s.MODES, horizontal=True)
        evs = view["events"].get(mode, [])
        case_filter = st.selectbox("Case", ["(all)"] + [x["case_key"] for x in c["cases"]])
        if case_filter != "(all)":
            evs = [e for e in evs if e["case_key"] == case_filter]
        st.dataframe(pd.DataFrame([{"seq": e["seq"], "case": e["case_key"], "type": e["type"],
                                    "layer": e["layer"], "details": json.dumps(e["details"])}
                                   for e in evs]), hide_index=True, use_container_width=True)

    with tab_report:
        st.text(s.render_report_markdown(c, run_id, view["report"]["content_sha256"]))
        if st.button("Regenerate report from stored events"):
            res = s.regenerate_report(eng, run_id)
            (st.success if res["identical"] else st.error)(
                f"New hash {res['content_sha256'][:16]}… identical to previous: {res['identical']}")
        st.download_button("Download report JSON", json.dumps(c, indent=2, default=str),
                           file_name=f"sentinel_report_{run_id[:8]}.json")


def page_history():
    st.header("History")
    st.dataframe(pd.DataFrame(s.list_runs(eng)), hide_index=True, use_container_width=True)


# ── navigation (top bar) ─────────────────────────────────────────────────────
RESULTS = st.Page(page_results, title="Results", icon=":material/analytics:", url_path="results")
nav = st.navigation([
    st.Page(page_new_comparison, title="New comparison", icon=":material/play_arrow:",
            url_path="new", default=True),
    RESULTS,
    st.Page(page_history, title="History", icon=":material/history:", url_path="history"),
    st.Page(page_scenarios, title="Scenarios", icon=":material/list:", url_path="scenarios"),
    st.Page(page_health, title="Health", icon=":material/monitor_heart:", url_path="health"),
], position="top")

# Fixed brand strip above Streamlit's own top bar, the same on every page.
# Streamlit has no API for this: the CSS shifts the internal .stApp container down and pins the strip
# in the gap, so re-check it after any Streamlit upgrade (the version is pinned in requirements.txt).
# Only constants go into this HTML, never document or database text.
# logo: a shield whose top edge forms cat ears, plus whiskers (Meow Geeks)
LOGO_SVG = ('<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" '
            'stroke-width="1.7" stroke-linejoin="round" stroke-linecap="round" aria-hidden="true">'
            '<path d="M4 5.5 5.2 1.8 9 4.2 12 3.4l3 .8 3.8-2.4L20 5.5v5.6c0 5.05-3.41 9.76-8 10.91'
            '-4.59-1.15-8-5.86-8-10.91Z"/>'
            '<path stroke-width="1.2" d="M6.5 11.4l3 .6M6.8 13.8l2.8-.6M17.5 11.4l-3 .6M17.2 13.8l-2.8-.6"/></svg>')
st.markdown("""
<style>
  .stApp { top: 2.75rem; height: calc(100dvh - 2.75rem); }
  .stApp::before {                      /* opaque backdrop that follows the light/dark theme */
    content: ""; position: fixed; top: 0; left: 0; right: 0; height: 2.75rem; z-index: 1000000;
    background: inherit; border-bottom: 1px solid rgba(128, 128, 128, 0.25);
  }
  .sentinel-brand {
    position: fixed; top: 0; left: 0; right: 0; height: 2.75rem; z-index: 1000001;
    display: flex; align-items: center; justify-content: space-between; padding: 0 1.25rem;
  }
  .sentinel-brand .name { display: flex; align-items: center; gap: 0.45rem;
                          font-size: 1.3rem; font-weight: 700; }
  .sentinel-brand .team { font-size: 0.85rem; opacity: 0.75; }
</style>
<div class="sentinel-brand">
  <span class="name">""" + LOGO_SVG + """Sentinel</span>
  <span class="team">Meow Geeks</span>
</div>
""", unsafe_allow_html=True)
st.caption(s.SIMULATED_LABEL)

# health check up front: a clear message beats a stack trace
try:
    eng = engine()
    info = s.check_connection(eng)
    if info["missing_tables"]:
        st.warning("Tables missing. Run `python sentinel.py init-db` in the terminal, then reload.")
        st.stop()
    s.cleanup_stale_runs(eng)
except s.ConfigError as exc:
    st.error(f"Configuration problem: {exc}")
    st.stop()
except Exception as exc:
    st.error(f"Database problem: {type(exc).__name__}: {exc}")
    st.stop()

nav.run()
