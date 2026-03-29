from __future__ import annotations

from typing import Any

from mcp_server.capabilities.bgp.correlation import build_grouped_incident
from mcp_server.capabilities.bgp.models import (
    BgpEventRecord,
    BgpFinding,
    BgpLogRecord,
    BgpNeighborRecord,
    BgpRouteRecord,
    BgpSnapshot,
)


ESTABLISHED_STATES = {"established", "up"}

# Severity ordering is used to keep findings stable and predictable for operators and tests.
# Higher severity findings appear first in the response.
SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "warning": 2,
    "info": 3,
}


def analyze_bgp_snapshot(
    *,
    fabric: str,
    device: str,
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    """
    Analyze a normalized BGP snapshot.

    The troubleshooting flow mirrors the operator workflow:
    1. session state first
    2. route visibility across Adj RIB In, Loc RIB, and Adj RIB Out
    3. best path hints
    4. event based instability signals
    5. correlated parent incident creation to reduce alert fatigue

    Check in 3 improves response usability in these ways:
    - findings are sorted in a stable order
    - a diagnosis_counts section is returned
    - a validation_summary section is returned
    - output shape becomes easier to test automatically
    """

    normalized = _normalize_snapshot(snapshot)

    findings: list[BgpFinding] = []

    findings.extend(_analyze_neighbor_sessions(normalized.neighbors, normalized.logs))
    findings.extend(
        _analyze_route_pipeline(
            adj_rib_in=normalized.adj_rib_in,
            loc_rib=normalized.loc_rib,
            adj_rib_out=normalized.adj_rib_out,
            logs=normalized.logs,
        )
    )
    findings.extend(_analyze_events(normalized.events, normalized.logs))

    # Sort findings so the output is deterministic and test friendly.
    findings = _sort_findings(findings)

    grouped_incident = build_grouped_incident(
        fabric=fabric,
        device=device,
        findings=findings,
        logs=[log.message for log in normalized.logs],
        correlation_window_seconds=normalized.correlation_window_seconds,
    )

    recommended_actions = _build_recommendations(findings, grouped_incident)
    summary, root_cause, confidence = _build_summary(findings, grouped_incident)
    diagnosis_counts = _build_diagnosis_counts(findings)
    validation_summary = _build_validation_summary(findings, grouped_incident)

    return {
        "summary": summary,
        "incident_type": (
            "bgp_correlated_failure" if grouped_incident is not None else "bgp_diagnostic"
        ),
        "root_cause": root_cause,
        "confidence": confidence,
        "snapshot_contract_version": "checkin_3",
        "correlation_window_seconds": normalized.correlation_window_seconds,
        "diagnosis_counts": diagnosis_counts,
        "validation_summary": validation_summary,
        "findings": [_finding_to_dict(finding) for finding in findings],
        "grouped_events": (
            grouped_incident.grouped_events if grouped_incident is not None else []
        ),
        "evidence": [finding.evidence for finding in findings],
        "recommended_actions": recommended_actions,
        "alert": (
            {
                "dedupe_key": grouped_incident.dedupe_key,
                "title": grouped_incident.title,
                "impact_summary": grouped_incident.impact_summary,
                "correlation_window_seconds": grouped_incident.correlation_window_seconds,
                "child_incidents": [
                    {
                        "finding_type": child.finding_type,
                        "summary": child.summary,
                        "peer": child.peer,
                        "prefix": child.prefix,
                        "severity": child.severity,
                        "confidence": child.confidence,
                        "occurred_at": child.occurred_at,
                    }
                    for child in grouped_incident.child_incidents
                ],
                "consolidated_logs": grouped_incident.consolidated_logs,
            }
            if grouped_incident is not None
            else None
        ),
    }


def _normalize_snapshot(raw_snapshot: dict[str, Any]) -> BgpSnapshot:
    """
    Normalize a raw snapshot dict into the internal BgpSnapshot structure.

    This gives the analyzer a predictable internal model while still allowing the request
    body to be permissive during adoption.
    """
    correlation_window_seconds = _safe_positive_int(
        raw_snapshot.get("correlation_window_seconds"),
        default=180,
    )

    neighbors = [
        BgpNeighborRecord(
            peer=str(item.get("peer") or item.get("neighbor") or "unknown"),
            session_state=str(item.get("session_state", "unknown")),
            prefixes_received=_maybe_int(item.get("prefixes_received")),
            prefixes_accepted=_maybe_int(item.get("prefixes_accepted")),
            prefixes_advertised=_maybe_int(item.get("prefixes_advertised")),
            best_path_count=_maybe_int(item.get("best_path_count")),
            shared_dependency=_maybe_str(item.get("shared_dependency")),
            last_error=_maybe_str(item.get("last_error")),
            last_event_at=_maybe_str(item.get("last_event_at")),
            address_family=str(item.get("address_family", "ipv4_unicast")),
            metadata=_safe_dict(item.get("metadata")),
        )
        for item in _as_list(raw_snapshot.get("neighbors"))
        if isinstance(item, dict)
    ]

    adj_rib_in = _normalize_routes(raw_snapshot.get("adj_rib_in"))
    loc_rib = _normalize_routes(raw_snapshot.get("loc_rib"))
    adj_rib_out = _normalize_routes(raw_snapshot.get("adj_rib_out"))

    events = [
        BgpEventRecord(
            event_type=str(item.get("type") or item.get("event_type") or "unknown"),
            peer=_maybe_str(item.get("peer")),
            prefix=_maybe_str(item.get("prefix")),
            shared_dependency=_maybe_str(item.get("shared_dependency")),
            severity=str(item.get("severity", "warning")),
            occurred_at=_maybe_str(item.get("occurred_at")),
            message=_maybe_str(item.get("message")),
            metadata=_safe_dict(item.get("metadata")),
        )
        for item in _as_list(raw_snapshot.get("events"))
        if isinstance(item, dict)
    ]

    logs = []
    for item in _as_list(raw_snapshot.get("logs")):
        if isinstance(item, str):
            logs.append(BgpLogRecord(message=item))
            continue

        if isinstance(item, dict):
            logs.append(
                BgpLogRecord(
                    message=str(item.get("message", "")),
                    occurred_at=_maybe_str(item.get("occurred_at")),
                    source=_maybe_str(item.get("source")),
                    peer=_maybe_str(item.get("peer")),
                    prefix=_maybe_str(item.get("prefix")),
                    shared_dependency=_maybe_str(item.get("shared_dependency")),
                    metadata=_safe_dict(item.get("metadata")),
                )
            )

    return BgpSnapshot(
        correlation_window_seconds=correlation_window_seconds,
        neighbors=neighbors,
        loc_rib=loc_rib,
        adj_rib_in=adj_rib_in,
        adj_rib_out=adj_rib_out,
        events=events,
        logs=logs,
        metadata=_safe_dict(raw_snapshot.get("metadata")),
    )


def _normalize_routes(raw_routes: Any) -> list[BgpRouteRecord]:
    """
    Normalize route lists for Adj RIB In, Loc RIB, and Adj RIB Out.
    """
    routes: list[BgpRouteRecord] = []

    for item in _as_list(raw_routes):
        if not isinstance(item, dict):
            continue

        prefix = str(item.get("prefix") or "")
        if not prefix:
            continue

        routes.append(
            BgpRouteRecord(
                prefix=prefix,
                peer=_maybe_str(item.get("peer")),
                next_hop=_maybe_str(item.get("next_hop")),
                reason=_maybe_str(item.get("reason")),
                best=bool(item.get("best", False)),
                shared_dependency=_maybe_str(item.get("shared_dependency")),
                address_family=str(item.get("address_family", "ipv4_unicast")),
                metadata=_safe_dict(item.get("metadata")),
            )
        )

    return routes


def _analyze_neighbor_sessions(
    neighbors: list[BgpNeighborRecord],
    logs: list[BgpLogRecord],
) -> list[BgpFinding]:
    findings: list[BgpFinding] = []

    for neighbor in neighbors:
        peer = neighbor.peer
        session_state = neighbor.session_state.lower()
        shared_dependency = neighbor.shared_dependency
        prefixes_received = neighbor.prefixes_received
        last_error = neighbor.last_error

        if session_state not in ESTABLISHED_STATES:
            summary = f"BGP session to {peer} is not established"
            root_hint = (
                str(shared_dependency)
                if shared_dependency
                else "peering_or_reachability_issue"
            )
            findings.append(
                BgpFinding(
                    finding_type="session_down",
                    severity="critical",
                    summary=summary,
                    peer=peer,
                    confidence=0.92,
                    occurred_at=neighbor.last_event_at,
                    evidence={
                        "session_state": session_state,
                        "shared_dependency": shared_dependency,
                        "last_error": last_error,
                        "address_family": neighbor.address_family,
                        "root_cause_hint": root_hint,
                    },
                    logs=_select_logs(logs, peer, session_state, last_error, shared_dependency),
                )
            )
            continue

        # Established but no received routes is often a sender or upstream issue before
        # local policy has a chance to accept anything.
        if prefixes_received == 0:
            findings.append(
                BgpFinding(
                    finding_type="peer_not_advertising",
                    severity="warning",
                    summary=f"BGP session to {peer} is established but no prefixes were received",
                    peer=peer,
                    confidence=0.78,
                    occurred_at=neighbor.last_event_at,
                    evidence={
                        "session_state": session_state,
                        "prefixes_received": prefixes_received,
                        "shared_dependency": shared_dependency,
                        "address_family": neighbor.address_family,
                        "root_cause_hint": "peer_not_advertising_or_upstream_issue",
                    },
                    logs=_select_logs(logs, peer, "prefix", "advertis", shared_dependency),
                )
            )

    return findings


def _analyze_route_pipeline(
    *,
    adj_rib_in: list[BgpRouteRecord],
    loc_rib: list[BgpRouteRecord],
    adj_rib_out: list[BgpRouteRecord],
    logs: list[BgpLogRecord],
) -> list[BgpFinding]:
    findings: list[BgpFinding] = []

    in_index = _index_routes(adj_rib_in)
    loc_index = _index_routes(loc_rib)
    out_index = _index_routes(adj_rib_out)

    all_prefixes = sorted(set(in_index) | set(loc_index) | set(out_index))

    for prefix in all_prefixes:
        in_routes = in_index.get(prefix, [])
        loc_routes = loc_index.get(prefix, [])
        out_routes = out_index.get(prefix, [])

        if in_routes and not loc_routes:
            route = in_routes[0]
            findings.append(
                BgpFinding(
                    finding_type="inbound_policy_drop",
                    severity="high",
                    summary=(
                        f"Prefix {prefix} reached Adj RIB In but did not enter Loc RIB"
                    ),
                    peer=route.peer,
                    prefix=prefix,
                    confidence=0.88,
                    evidence={
                        "table": "adj_rib_in_to_loc_rib",
                        "reason": route.reason,
                        "shared_dependency": route.shared_dependency,
                        "address_family": route.address_family,
                        "root_cause_hint": "inbound_policy_or_validation_failure",
                    },
                    logs=_select_logs(logs, prefix, "policy", "validation", route.shared_dependency),
                )
            )

        if loc_routes and not out_routes:
            route = loc_routes[0]
            findings.append(
                BgpFinding(
                    finding_type="outbound_policy_drop",
                    severity="high",
                    summary=(
                        f"Prefix {prefix} exists in Loc RIB but is absent from Adj RIB Out"
                    ),
                    peer=route.peer,
                    prefix=prefix,
                    confidence=0.86,
                    evidence={
                        "table": "loc_rib_to_adj_rib_out",
                        "reason": route.reason,
                        "shared_dependency": route.shared_dependency,
                        "address_family": route.address_family,
                        "root_cause_hint": "outbound_policy_drop",
                    },
                    logs=_select_logs(logs, prefix, "outbound", "advertis", route.shared_dependency),
                )
            )

        # A route in Loc RIB without any best path marker is suspicious and worth
        # surfacing even if the full BGP attribute set is not present yet.
        if loc_routes and not any(route.best for route in loc_routes):
            route = loc_routes[0]
            findings.append(
                BgpFinding(
                    finding_type="best_path_issue",
                    severity="warning",
                    summary=f"Prefix {prefix} is in Loc RIB but no best path is selected",
                    prefix=prefix,
                    confidence=0.72,
                    evidence={
                        "table": "loc_rib",
                        "route_count": len(loc_routes),
                        "shared_dependency": route.shared_dependency,
                        "address_family": route.address_family,
                        "root_cause_hint": "unexpected_best_path_selection",
                    },
                    logs=_select_logs(logs, prefix, "best", "path", route.shared_dependency),
                )
            )

    return findings


def _analyze_events(
    events: list[BgpEventRecord],
    logs: list[BgpLogRecord],
) -> list[BgpFinding]:
    findings: list[BgpFinding] = []

    for event in events:
        event_type = event.event_type.lower()

        if event_type in {"hold_timer_expired", "peer_flap", "session_flap"}:
            findings.append(
                BgpFinding(
                    finding_type="session_unstable",
                    severity="high",
                    summary=f"BGP session instability detected for {event.peer or 'unknown'}",
                    peer=event.peer,
                    prefix=event.prefix,
                    confidence=0.8,
                    occurred_at=event.occurred_at,
                    evidence={
                        "event_type": event_type,
                        "shared_dependency": event.shared_dependency,
                        "root_cause_hint": str(event.shared_dependency or "session_instability"),
                    },
                    logs=_select_logs(
                        logs,
                        event.peer,
                        event.prefix,
                        "hold",
                        "flap",
                        event.shared_dependency,
                    ),
                )
            )

    return findings


def _build_recommendations(
    findings: list[BgpFinding],
    grouped_incident: Any,
) -> list[dict[str, Any]]:
    """
    Build safe read only recommendations.

    Check in 3 still keeps the system in Option A. All recommendations remain read only.
    """
    recommendations: list[dict[str, Any]] = []
    seen_titles: set[str] = set()

    for finding in findings:
        if finding.finding_type == "session_down":
            title = "Verify peer reachability and session parameters"
            summary = (
                "Inspect peer reachability, remote ASN, update source, transport reachability, "
                "and the last error before considering any reset"
            )
        elif finding.finding_type == "peer_not_advertising":
            title = "Verify upstream advertisement state"
            summary = (
                "Inspect the upstream peer and Adj RIB Out on the sender to confirm whether "
                "the prefix set was actually advertised"
            )
        elif finding.finding_type == "inbound_policy_drop":
            title = "Inspect inbound policy and validation state"
            summary = (
                "Review inbound policy, validation outcomes, and route acceptance rules for the "
                "affected peer and prefix"
            )
        elif finding.finding_type == "outbound_policy_drop":
            title = "Inspect outbound policy on the advertising node"
            summary = (
                "Review outbound policy, route export filters, and advertisement eligibility for "
                "the affected prefix"
            )
        else:
            title = "Inspect best path and convergence inputs"
            summary = (
                "Review best path inputs and route selection evidence before taking any action"
            )

        if title in seen_titles:
            continue
        seen_titles.add(title)

        recommendations.append(
            {
                "title": title,
                "summary": summary,
                "action_type": "read_only_validation",
            }
        )

    if grouped_incident is not None:
        recommendations.append(
            {
                "title": "Review grouped incident before alert fan out",
                "summary": (
                    "Treat this as one parent incident and suppress duplicate child pages while "
                    "the parent incident is active"
                ),
                "action_type": "alert_correlation_guidance",
            }
        )

    return recommendations


def _build_summary(
    findings: list[BgpFinding],
    grouped_incident: Any,
) -> tuple[str, str, float]:
    if grouped_incident is not None:
        return (
            f"Correlated BGP incident on grouped dependency {grouped_incident.root_cause}",
            grouped_incident.root_cause,
            0.88,
        )

    if not findings:
        return (
            "No deterministic BGP issue was identified from the provided snapshot",
            "no_issue_detected",
            0.55,
        )

    top = findings[0]
    root_cause = str(top.evidence.get("root_cause_hint") or top.finding_type)
    return (top.summary, root_cause, top.confidence)


def _build_diagnosis_counts(findings: list[BgpFinding]) -> dict[str, int]:
    """
    Build counts by finding type.

    This is useful for validation, dashboards, and future Kafka aggregation summaries.
    """
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.finding_type] = counts.get(finding.finding_type, 0) + 1
    return counts


def _build_validation_summary(
    findings: list[BgpFinding],
    grouped_incident: Any,
) -> dict[str, Any]:
    """
    Build a compact validation summary that is easy to assert in tests.
    """
    return {
        "finding_count": len(findings),
        "has_grouped_alert": grouped_incident is not None,
        "highest_severity": findings[0].severity if findings else "info",
        "top_finding_type": findings[0].finding_type if findings else None,
    }


def _sort_findings(findings: list[BgpFinding]) -> list[BgpFinding]:
    """
    Sort findings in a deterministic order.

    Order:
    severity
    confidence descending
    finding type
    peer
    prefix
    """
    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(finding.severity, 99),
            -finding.confidence,
            finding.finding_type,
            finding.peer or "",
            finding.prefix or "",
        ),
    )


def _index_routes(routes: list[BgpRouteRecord]) -> dict[str, list[BgpRouteRecord]]:
    indexed: dict[str, list[BgpRouteRecord]] = {}
    for route in routes:
        if not route.prefix:
            continue
        indexed.setdefault(route.prefix, []).append(route)
    return indexed


def _finding_to_dict(finding: BgpFinding) -> dict[str, Any]:
    return {
        "finding_type": finding.finding_type,
        "severity": finding.severity,
        "summary": finding.summary,
        "peer": finding.peer,
        "prefix": finding.prefix,
        "confidence": finding.confidence,
        "occurred_at": finding.occurred_at,
        "evidence": finding.evidence,
        "logs": finding.logs,
    }


def _select_logs(logs: list[BgpLogRecord], *terms: Any) -> list[str]:
    """
    Select relevant log lines for a finding.

    The goal is not perfect ranking yet, but enough useful evidence so the grouped alert
    carries readable operator context.
    """
    normalized_terms = [str(term).lower() for term in terms if term not in (None, "")]
    if not normalized_terms:
        return []

    selected: list[str] = []
    for record in logs:
        searchable = " ".join(
            [
                record.message,
                record.source or "",
                record.peer or "",
                record.prefix or "",
                record.shared_dependency or "",
            ]
        ).lower()

        if any(term in searchable for term in normalized_terms):
            selected.append(record.message)

    return selected[:20]


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _safe_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _safe_positive_int(value: Any, default: int) -> int:
    parsed = _maybe_int(value)
    if parsed is None or parsed <= 0:
        return default
    return parsed


def _maybe_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _maybe_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)
