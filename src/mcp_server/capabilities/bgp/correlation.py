from __future__ import annotations

from collections import defaultdict
from typing import Any

from mcp_server.capabilities.bgp.models import (
    BgpChildIncident,
    BgpFinding,
    BgpGroupedIncident,
)


def build_grouped_incident(
    *,
    fabric: str,
    device: str,
    findings: list[BgpFinding],
    logs: list[str],
    correlation_window_seconds: int,
) -> BgpGroupedIncident | None:
    """
    Correlate related BGP findings into one grouped incident.

    Check in 2 improves the first pass grouping logic in these ways:
    - honors a correlation window value from the snapshot
    - groups by shared dependency when present
    - falls back to root cause hint when needed
    - creates child incident records so downstream systems can page once on the parent
      while still preserving per symptom detail

    This is intentionally deterministic. It is simple to reason about and easy to test.
    A future Kafka based correlator can use the same parent and child structure when we
    move from per request grouping to streaming incident aggregation.
    """

    if len(findings) < 2:
        return None

    dependency_buckets: dict[str, list[BgpFinding]] = defaultdict(list)

    for finding in findings:
        evidence = finding.evidence
        dependency = _resolve_grouping_key(finding)
        dependency_buckets[dependency].append(finding)

    # Select the largest correlated bucket. This is the parent candidate most likely to
    # represent the actual root issue behind many raw BGP symptoms.
    selected_dependency = max(
        dependency_buckets,
        key=lambda dependency: len(dependency_buckets[dependency]),
    )
    selected_findings = dependency_buckets[selected_dependency]

    # Do not group if the selected bucket is not meaningfully larger than a single issue.
    if len(selected_findings) < 2:
        return None

    grouped_events: list[dict[str, Any]] = []
    evidence_bundle: list[dict[str, Any]] = []
    consolidated_logs: list[str] = []
    child_incidents: list[BgpChildIncident] = []

    for finding in selected_findings:
        grouped_events.append(
            {
                "finding_type": finding.finding_type,
                "peer": finding.peer,
                "prefix": finding.prefix,
                "summary": finding.summary,
                "confidence": finding.confidence,
                "occurred_at": finding.occurred_at,
            }
        )

        evidence_bundle.append(finding.evidence)

        child_incidents.append(
            BgpChildIncident(
                finding_type=finding.finding_type,
                summary=finding.summary,
                peer=finding.peer,
                prefix=finding.prefix,
                severity=finding.severity,
                confidence=finding.confidence,
                occurred_at=finding.occurred_at,
            )
        )

        consolidated_logs.extend(finding.logs)

    # Dedupe logs while preserving order so the final grouped alert carries a readable and
    # consolidated operator timeline.
    unique_logs = list(dict.fromkeys(consolidated_logs + logs))

    dedupe_key = (
        f"fabric:{fabric}:device:{device}:root:{selected_dependency}:"
        f"window:{correlation_window_seconds}"
    )

    return BgpGroupedIncident(
        dedupe_key=dedupe_key,
        title=f"BGP correlated incident on {device}",
        root_cause=selected_dependency,
        impact_summary=(
            f"{len(selected_findings)} related BGP symptoms were grouped into one incident"
        ),
        correlation_window_seconds=correlation_window_seconds,
        child_incidents=child_incidents,
        grouped_events=grouped_events,
        consolidated_logs=unique_logs,
        evidence=evidence_bundle,
    )


def _resolve_grouping_key(finding: BgpFinding) -> str:
    """
    Resolve the grouping key used for alert rollup.

    Preference order:
    1. shared dependency, because that usually reflects topology or control plane reality
    2. root cause hint, because the analyzer may know the problem class
    3. finding type as the last deterministic fallback
    """
    evidence = finding.evidence
    dependency = evidence.get("shared_dependency")
    if dependency:
        return str(dependency)

    root_cause_hint = evidence.get("root_cause_hint")
    if root_cause_hint:
        return str(root_cause_hint)

    return finding.finding_type
