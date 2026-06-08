"""
rule_review/server.py — optional Flask dashboard for the human-in-the-loop review gate.

This is the analyst's screen: a queue of LLM-generated detections, each with a plain-English
explanation, its dry-run blast-radius, a confidence score, and APPROVE / REJECT buttons.
Approving a rule deploys it to the git rule store (via GitDeployer); rejecting drops it.

Flask is an OPTIONAL dependency — it is imported lazily inside create_app() so that
`import rule_review` (and the entire tested core: queue, dry_runner, explainer, deployer)
works with the standard library alone. Install Flask only if you want this UI:

    pip install Flask
    python -m rule_review.server            # serves http://127.0.0.1:5001

The dashboard reads/writes the same results/rule_review_queue.json the CLI and orchestrator
use, so reviews are consistent across every entry point.
"""
from __future__ import annotations

from .queue import ReviewQueue
from .explainer import explain, recommendation
from .deployer import GitDeployer

_PAGE = """<!doctype html>
<title>PurpleForge — Rule Review</title>
<style>
 body{background:#0e1117;color:#e6edf3;font:14px/1.5 system-ui,Segoe UI,sans-serif;margin:0;padding:24px}
 h1{font-size:20px;margin:0 0 4px} .sub{color:#8b949e;margin-bottom:20px}
 .counts span{display:inline-block;margin-right:14px;padding:3px 10px;border-radius:12px;background:#161b22;border:1px solid #30363d}
 .card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin:12px 0}
 .tech{font-weight:600;color:#d2a8ff} .rec{float:right;font-weight:700;padding:2px 10px;border-radius:6px}
 .APPROVE{background:#1a4d2e;color:#7ee787} .REJECT{background:#5c1a1a;color:#ff7b72} .REVIEW{background:#5c4a1a;color:#f2cc60}
 pre{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:10px;overflow:auto;white-space:pre-wrap;color:#c9d1d9}
 .explain{white-space:pre-wrap;color:#adbac7;margin:8px 0}
 form{display:inline} button{font:inherit;border:0;border-radius:6px;padding:7px 16px;margin-right:8px;cursor:pointer}
 .approve{background:#238636;color:#fff} .reject{background:#da3633;color:#fff}
 .flash{padding:10px 14px;border-radius:6px;margin-bottom:14px;background:#161b22;border:1px solid #30363d}
 .meta{color:#8b949e;font-size:12px} a{color:#58a6ff;text-decoration:none}
</style>
<h1>PurpleForge — Rule Review Queue</h1>
<div class="sub">Human-in-the-loop gate. Nothing deploys to the rule store until you approve it.</div>
{flash}
<div class="counts">{counts}</div>
{cards}
"""

_CARD = """<div class="card">
  <span class="rec {rec}">{rec}</span>
  <span class="tech">{technique}</span> &mdash; <code>{rule_name}</code>
  <div class="explain">{explanation}</div>
  <pre>{spl}</pre>
  <div class="meta">id {id} · status <b>{status}</b> · created {created}</div>
  {actions}
</div>"""

_ACTIONS = """<div style="margin-top:10px">
  <form method="post" action="/rule/{id}/approve">
    <input type="hidden" name="reviewer" value="analyst">
    <button class="approve">✓ Approve &amp; deploy</button>
  </form>
  <form method="post" action="/rule/{id}/reject">
    <input type="hidden" name="reviewer" value="analyst">
    <button class="reject">✗ Reject</button>
  </form>
</div>"""


def _esc(s) -> str:
    from html import escape
    return escape(str(s))


def create_app(queue: ReviewQueue | None = None, deployer: GitDeployer | None = None):
    """
    Build the Flask app. Injectable queue/deployer make this testable with app.test_client().
    Flask is imported here (not at module top) so the package stays import-able without it.
    """
    try:
        from flask import Flask, request, redirect
    except ImportError as e:  # pragma: no cover - exercised only without Flask installed
        raise RuntimeError(
            "Flask is required for the review dashboard. Install it with `pip install Flask`. "
            "The rest of rule_review (queue, dry_runner, explainer, deployer) needs no extra deps."
        ) from e

    app = Flask(__name__)
    q = queue or ReviewQueue()
    dep = deployer or GitDeployer()

    def render(flash: str = "") -> str:
        counts = q.counts()
        counts_html = "".join(
            f"<span>{_esc(k)}: {_esc(v)}</span>" for k, v in sorted(counts.items())
        ) or "<span>queue empty</span>"
        # Pending first (what needs action), then everything else, newest-first within each.
        items = q.list()
        items.sort(key=lambda r: (r.status != "pending", -r.created_ts))
        cards = []
        for r in items:
            actions = _ACTIONS.format(id=_esc(r.id)) if r.status == "pending" else ""
            cards.append(_CARD.format(
                rec=_esc(recommendation(r)),
                technique=_esc(r.technique),
                rule_name=_esc(r.rule_name),
                explanation=_esc(r.explanation or explain(r)),
                spl=_esc(r.spl),
                id=_esc(r.id),
                status=_esc(r.status),
                created=_esc(r.created_ts),
                actions=actions,
            ))
        flash_html = f'<div class="flash">{flash}</div>' if flash else ""
        return _PAGE.format(
            flash=flash_html,
            counts=counts_html,
            cards="".join(cards) or "<p>No rules in the queue.</p>",
        )

    @app.get("/")
    def index():
        return render()

    @app.post("/rule/<rule_id>/approve")
    def approve(rule_id: str):
        reviewer = request.form.get("reviewer", "analyst")
        r = q.approve(rule_id, reviewer=reviewer)
        if r is None:
            return redirect("/")
        result = dep.deploy(r, reviewer=reviewer)
        if result.get("committed"):
            q.mark_deployed(rule_id)
            msg = f"Deployed {r.rule_name} — commit {result.get('commit_sha', '')[:10]}"
        else:
            msg = f"Approved {r.rule_name}, but deploy did not commit: {result.get('error', 'unknown')}"
        # PRG: re-render with a flash (kept simple; no session needed).
        return render(_esc(msg))

    @app.post("/rule/<rule_id>/reject")
    def reject(rule_id: str):
        reviewer = request.form.get("reviewer", "analyst")
        notes = request.form.get("notes", "")
        r = q.reject(rule_id, reviewer=reviewer, notes=notes)
        msg = f"Rejected {r.rule_name}" if r else "Rule not found or already decided"
        return render(_esc(msg))

    return app


def main() -> None:
    app = create_app()
    # 5001 to avoid colliding with other local Flask defaults; bind localhost only.
    app.run(host="127.0.0.1", port=5001, debug=False)


if __name__ == "__main__":
    main()
