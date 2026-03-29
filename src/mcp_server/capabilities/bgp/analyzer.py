from __future__ import annotations

from typing import Any

from mcp_server.capabilities.bgp.correlation import build_grouped_incident
from mcp_server.capabilities.bgp.models import BgpFinding


ESTABLISHED_STATES = {"established", "up"}


def analyze_bgp_snapshot(
    *,
    fabric: str,
    device: str,
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    """
    Analyze a normalized BGP snapshot.

    The troubleshooting flow intentionally mirrors the operator workflow:
    session state first, then route visibility across Adj RIB In, Loc RIB, and Adj RIB Out,
    then best path hints, and finally event correlation to suppress noisy child alerts.
    """

    neighbors = _as_list(snapshot.get("neighbors"))
    loc_rib = _as_list(snapshot.get("loc_rib"))
    adj_rib_in = _as_list(snapshot.get("adj_rib_in"))
    adj_rib_out = _as_list(snapshot.get("adj_rib_out"))
    events = _as_list(snapshot.get("events"))
    logs = [str(item) for item in _as_list(snapshot.get("logs"))]

    findings: list[BgpFinding] = []

    # Session analysis comes first because a down session changes the meaning of all route
    # tables. There is little value in debating policies if the peering is not up.
    findings.extend(_analyze_neighbor_sessions(neighbors, logs))

    # Route pipeline analysis follows the operational BGP path.
    findings.extend(
        _analyze_route_pipeline(
            adj_rib_in=adj_rib_in,
            loc_rib=loc_rib,
            adj_rib_out=adj_rib_out,
            logs=logs,
        )
    )

    # Event based hints help when explicit table records are sparse.
    findings.extend(_analyze_events(events, logs))

    grouped_incident = build_grouped_incident(
        fabric=fabric,
        device=device,
        findings=findings,
        logs=logs,
    )

    recommended_actions = _build_recommendations(findings, grouped_incident)
    summary, root_cause, confidence = _build_summary(findings, grouped_incident)

    return {
        "summary": summary,
        "incident_type": (
            "bgp_correlated_failure" if grouped_incident is not None else "bgp_diagnostic"
        ),
        "root_cause": root_cause,
        "confidence": confidence,
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
                "consolidated_logs": grouped_incident.consolidated_logs,
            }
            if grouped_incident is not None
            else None
        ),
    }


def _analyze_neighbor_sessions(
    neighbors: list[dict[str, Any]],
    logs: list[str],
) -> list[BgpFinding]:
    findings: list[BgpFinding] = []

    for neighbor in neighbors:
        peer = str(neighbor.get("peer") or neighbor.get("neighbor") or "unknown")
        session_state = str(neighbor.get("session_state", "unknown")).lower()
        shared_dependency = neighbor.get("shared_dependency")
        prefixes_received = _maybe_int(neighbor.get("prefixes_received"))
        last_error = neighbor.get("last_error")

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
                    evidence={
                        "session_state": session_state,
                        "shared_dependency": shared_dependency,
                        "last_error": last_error,
                        "root_cause_hint": root_hint,
                    },
                    logs=_select_logs(logs, peer, session_state, last_error),
                )
            )
            continue

        # An established session with no received prefixes often means the upstream peer
        # is not advertising anything, or an upstream issue exists before policy.
        if prefixes_received == 0:
            findings.append(
                BgpFinding(
                    finding_type="peer_not_advertising",
                    severity="warning",
                    summary=f"BGP session to {peer} is established but no prefixes were received",
                    peer=peer,
                    confidence=0.78,
                    evidence={
                        "session_state": session_state,
                        "prefixes_received": prefixes_received,
                        "shared_dependency": shared_dependency,
                        "root_cause_hint": "peer_not_advertising_or_upstream_issue",
                    },
                    logs=_select_logs(logs, peer, "prefix", "advertis"),
                )
            )

    return findings


def _analyze_route_pipeline(
    *,
    adj_rib_in: list[dict[str, Any]],
    loc_rib: list[dict[str, Any]],
    adj_rib_out: list[dict[str, Any]],
    logs: list[str],
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
                    peer=str(route.get("peer") or "unknown"),
                    prefix=prefix,
                    confidence=0.88,
                    evidence={
                        "table": "adj_rib_in_to_loc_rib",
                        "reason": route.get("reason"),
                        "shared_dependency": route.get("shared_dependency"),
                        "root_cause_hint": "inbound_policy_or_validation_failure",
                    },
                    logs=_select_logs(logs, prefix, "policy", "validation"),
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
                    peer=str(route.get("peer") or "unknown"),
                    prefix=prefix,
                    confidence=0.86,
                    evidence={
                        "table": "loc_rib_to_adj_rib_out",
                        "reason": route.get("reason"),
                        "shared_dependency": route.get("shared_dependency"),
                        "root_cause_hint": "outbound_policy_drop",
                    },
                    logs=_select_logs(logs, prefix, "outbound", "advertis"),
                )
            )

        # If the route is present in Loc RIB but no best path is marked, call out the issue
        # explicitly. This is a simple first pass that can later evolve into detailed best
        # path reasoning using attributes such as local preference and AS path.
        if loc_routes and not any(bool(route.get("best")) for route in loc_routes):
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
                        "root_cause_hint": "unexpected_best_path_selection",
                    },
                    logs=_select_logs(logs, prefix, "best", "path"),
                )
            )

    return findings


def _analyze_events(
    events: list[dict[str, Any]],
    logs: list[str],
) -> list[BgpFinding]:
    findings: list[BgpFinding] = []

    for event in events:
        event_type = str(event.get("type") or event.get("event_type") or "").lower()
        peer = str(event.get("peer") or "unknown")
        shared_dependency = event.get("shared_dependency")

        if event_type in {"hold_timer_expired", "peer_flap", "session_flap"}:
            findings.append(
                BgpFinding(
                    finding_type="session_unstable",
                    severity="high",
                    summary=f"BGP session instability detected for {peer}",
                    peer=peer,
                    confidence=0.8,
                    evidence={
                        "event_type": event_type,
                        "shared_dependency": shared_dependency,
                        "root_cause_hint": str(shared_dependency or "session_instability"),
                    },
                    logs=_select_logs(logs, peer, "hold", "flap"),
                )
            )

    return findings


def _build_recommendations(
    findings: list[BgpFinding],
    grouped_incident: Any,
) -> list[dict[str, Any]]:
    """
    Build safe read only recommendations.

    Check in 1 deliberately avoids automated changes. Recommendations are phrased as
    validation steps so the operator can inspect the right place without any write action.
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
                    "Treat this as one parent incident and avoid paging separately for each child "
                    "symptom unless the grouped incident is disproven"
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


def _index_routes(routes: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    indexed: dict[str, list[dict[str, Any]]] = {}
    for route in routes:
        prefix = str(route.get("prefix") or "")
        if not prefix:
            continue
        indexed.setdefault(prefix, []).append(route)
    return indexed


def _finding_to_dict(finding: BgpFinding) -> dict[str, Any]:
    return {
        "finding_type": finding.finding_type,
        "severity": finding.severity,
        "summary": finding.summary,
        "peer": finding.peer,
        "prefix": finding.prefix,
        "confidence": finding.confidence,
        "evidence": finding.evidence,
        "logs": finding.logs,
    }


def _select_logs(logs: list[str], *terms: Any) -> list[str]:
    normalized_terms = [str(term).lower() for term in terms if term not in (None, "")]
    if not normalized_terms:
        return []

    selected: list[str] = []
    for line in logs:
        lower = line.lower()
        if any(term in lower for term in normalized_terms):
            selected.append(line)
    return selected[:20]


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _maybe_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
