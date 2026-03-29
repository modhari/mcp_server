from __future__ import annotations

from collections import defaultdict
from typing import Any

from mcp_server.capabilities.bgp.models import BgpFinding, BgpGroupedIncident


def build_grouped_incident(
    *,
    fabric: str,
    device: str,
    findings: list[BgpFinding],
    logs: list[str],
) -> BgpGroupedIncident | None:
    """
    Correlate related BGP findings into one grouped incident.

    The first version intentionally stays deterministic and easy to reason about.
    It looks for repeated symptoms that share the same dependency or root cause pattern.
    This is where we directly address alert fatigue by preferring one parent incident over
    many child alerts.
    """

    if len(findings) < 2:
        return None

    dependency_buckets: dict[str, list[BgpFinding]] = defaultdict(list)

    for finding in findings:
        evidence = finding.evidence
        dependency = str(
            evidence.get("shared_dependency")
            or evidence.get("root_cause_hint")
            or finding.finding_type
        )
        dependency_buckets[dependency].append(finding)

    # Pick the largest correlated bucket. This favors grouping cascades such as many
    # neighbor failures behind one route reflector or one policy domain issue.
    selected_dependency = max(
        dependency_buckets,
        key=lambda dependency: len(dependency_buckets[dependency]),
    )
    selected_findings = dependency_buckets[selected_dependency]

    if len(selected_findings) < 2:
        return None

    grouped_events: list[dict[str, Any]] = []
    evidence_bundle: list[dict[str, Any]] = []
    consolidated_logs: list[str] = []

    for finding in selected_findings:
        grouped_events.append(
            {
                "finding_type": finding.finding_type,
                "peer": finding.peer,
                "prefix": finding.prefix,
                "summary": finding.summary,
                "confidence": finding.confidence,
            }
        )
        evidence_bundle.append(finding.evidence)
        consolidated_logs.extend(finding.logs)

    # Dedupe logs while preserving order. Consolidated logs are what downstream alerting
    # should carry so responders get context in one place.
    unique_logs = list(dict.fromkeys(consolidated_logs + logs))

    dedupe_key = (
        f"fabric:{fabric}:device:{device}:root:{selected_dependency}"
    )

    return BgpGroupedIncident(
        dedupe_key=dedupe_key,
        title=f"BGP correlated incident on {device}",
        root_cause=selected_dependency,
        impact_summary=(
            f"{len(selected_findings)} related BGP symptoms were grouped into one incident"
        ),
        grouped_events=grouped_events,
        consolidated_logs=unique_logs,
        evidence=evidence_bundle,
    )
