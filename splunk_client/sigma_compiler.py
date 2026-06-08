"""
Sigma compiler — turn platform-agnostic Sigma YAML detections into
executable Splunk SPL (and other SIEM dialects, to prove portability).

WHY SIGMA
---------
A single Sigma rule compiles to Splunk SPL, Elastic Lucene/EQL, Microsoft
Sentinel KQL, QRadar AQL, Chronicle, and 20+ other SIEMs via pySigma.
"What YARA is to files, Sigma is to logs." PurpleForge's Blue agent authors
detections in Sigma so that every rule — baseline AND every LLM-generated
rule — is portable to any SIEM, not locked to Splunk. This is the concrete
answer to "integratable into any system anywhere."

DESIGN NOTES
------------
* Our attack events arrive via HEC into a Splunk index (e.g. arena_attacks),
  not a WinEventLog source. So we compile WITHOUT the Windows source-adding
  pipeline and instead scope every search to the configured index.
* Rules reference the Splunk-extracted field `EventCode` directly (idiomatic
  for Windows Security detections), which lets a single rule span multiple
  event types via `condition: a or b or c` — matching our multi-anchor design.
* Sigma's aggregation support is intentionally limited; stateful threshold
  detections (e.g. password-spray dc()/count) remain native SPL. We do not
  over-claim Sigma coverage.
"""
from __future__ import annotations

import re

try:
    from sigma.collection import SigmaCollection
    from sigma.backends.splunk import SplunkBackend
    _SIGMA_AVAILABLE = True
except ImportError:  # pragma: no cover - dependency guard
    _SIGMA_AVAILABLE = False

# The Windows pipeline (if ever used) prefixes `source="WinEventLog:..."`.
# We strip it defensively so searches scope to our HEC index instead.
_SOURCE_CLAUSE = re.compile(r'source="WinEventLog:[^"]*"\s*')


class SigmaError(Exception):
    """Raised when a Sigma rule is invalid or cannot be compiled."""


def is_available() -> bool:
    """True if pySigma + the Splunk backend are installed."""
    return _SIGMA_AVAILABLE


def compile_to_spl(sigma_yaml: str, index: str = "arena_attacks") -> str:
    """
    Compile one Sigma rule (YAML string) to an executable SPL search,
    scoped to `index`. Does NOT append the `| eval technique=...` tag —
    the caller adds that so the scorer can attribute hits.

    Raises SigmaError on invalid Sigma or an unconvertible construct.
    """
    if not _SIGMA_AVAILABLE:
        raise SigmaError("pySigma not installed (pip install pysigma pysigma-backend-splunk)")
    try:
        collection = SigmaCollection.from_yaml(sigma_yaml)
        backend = SplunkBackend()
        # Expand multi-value fields to explicit OR clauses instead of `field IN (...)`.
        # Splunk's IN with quoted wildcards is a gray area; OR is unambiguously correct.
        backend.convert_or_as_in = False
        # Force full parenthesization. Without IN to group values, pySigma would
        # otherwise omit parens and Splunk's AND-binds-tighter-than-OR precedence
        # would mis-parse multi-value conditions (a precision-killing bug).
        backend.parenthesize = True
        out = backend.convert(collection)
    except Exception as exc:  # pySigma raises many subtypes; normalize them
        raise SigmaError(f"Sigma->SPL compile failed: {exc}") from exc
    if not out:
        raise SigmaError("Sigma compiled to an empty query")
    spl = _SOURCE_CLAUSE.sub("", out[0]).strip()
    return f"index={index} {spl}"


def compile_to_elastic(sigma_yaml: str) -> str | None:
    """
    Compile to Elastic Lucene to demonstrate cross-SIEM portability.
    Returns None if the Elastic backend isn't installed (optional dep).
    """
    try:
        from sigma.backends.elasticsearch import LuceneBackend
    except ImportError:
        return None
    try:
        out = LuceneBackend().convert(SigmaCollection.from_yaml(sigma_yaml))
        return out[0] if out else None
    except Exception:
        return None


def compile_to_sentinel(sigma_yaml: str) -> str | None:
    """
    Compile to Microsoft Sentinel KQL (optional dep). Returns None if the
    backend isn't installed or the rule can't be converted.
    """
    try:
        from sigma.backends.microsoft365defender import MicrosoftXDRBackend  # type: ignore
        backend = MicrosoftXDRBackend()
    except ImportError:
        return None
    try:
        out = backend.convert(SigmaCollection.from_yaml(sigma_yaml))
        return out[0] if out else None
    except Exception:
        return None


def validate(sigma_yaml: str, index: str = "arena_attacks") -> tuple[bool, str]:
    """
    Dry-run: does this Sigma YAML parse and compile to SPL?
    Returns (ok, compiled_spl_or_error_message).
    """
    try:
        return True, compile_to_spl(sigma_yaml, index=index)
    except SigmaError as exc:
        return False, str(exc)
    except Exception as exc:  # pragma: no cover - safety net
        return False, f"unexpected error: {exc}"


def portability_report(sigma_yaml: str, index: str = "arena_attacks") -> dict[str, str | None]:
    """
    Compile the same Sigma rule to every available backend. Used by the
    export tool and demo to SHOW that one detection runs on many SIEMs.
    """
    report: dict[str, str | None] = {}
    try:
        report["splunk_spl"] = compile_to_spl(sigma_yaml, index=index)
    except SigmaError as exc:
        report["splunk_spl"] = f"ERROR: {exc}"
    report["elastic_lucene"] = compile_to_elastic(sigma_yaml)
    report["sentinel_kql"] = compile_to_sentinel(sigma_yaml)
    return report
