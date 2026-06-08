"""
rule_review — human-in-the-loop review gate for LLM-generated detection rules.

In the arena Blue auto-deploys every rule it writes. No real SOC does that: an
LLM-authored detection goes into a review QUEUE, an analyst sees an explanation and
a dry-run blast-radius, and only on APPROVAL is it committed to the rule store
(detection-as-code, via git). This package implements that workflow.

Core (no external deps, fully testable):
  queue.ReviewQueue        — persistent pending-rule queue + confidence scoring
  dry_runner.DryRunner     — count a candidate rule's hits / estimated FPs
  explainer.explain        — human-readable summary of what a rule does
  deployer.GitDeployer     — commit an approved rule to the rule store

UI (optional, needs Flask):
  server                   — `python -m rule_review.server` review dashboard
"""
from .queue import ReviewQueue, PendingRule, compute_confidence

__all__ = ["ReviewQueue", "PendingRule", "compute_confidence"]
