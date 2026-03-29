from __future__ import annotations

from typing import Any

from mcp_server.capabilities.bgp.correlation import build_grouped_incident
from mcp_server.capabilities.bgp.models import (
    BgpEventRecord,
    BgpFinding,
    BgpGroupedIncident,
    BgpLogRecord,
    BgpNeighborRecord,
    BgpProposedAction,
    BgpRouteRecord,
    BgpSnapshot,
)


ESTABLISHED_STATES = {"established", "up"}

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

    Check in 4:
    - Adds proposed actions
    - Adds approval summary
    - Keeps execution disabled
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

    findings = _sort_findings(findings)

    grouped_incident = build_grouped_incident(
        fabric=fabric,
        device=device,
        findings=findings,
        logs=[log.message for log in normalized.logs],
        correlation_window_seconds=normalized.correlation_window_seconds,
    )

    recommended_actions = _build_recommendations(findings, grouped_incident)
    proposed_actions = _build_proposed_actions(
        fabric=fabric,
        device=device,
        findings=findings,
        grouped_incident=grouped_incident,
    )
    approval_summary = _build_approval_summary(proposed_actions)

    summary, root_cause, confidence = _build_summary(findings, grouped_incident)

    return {
        "summary": summary,
        "incident_type": (
            "bgp_correlated_failure" if grouped_incident else "bgp_diagnostic"
        ),
        "root_cause": root_cause,
        "confidence": confidence,
        "snapshot_contract_version": "checkin_4",
        "approval_summary": approval_summary,
        "findings": [_finding_to_dict(f) for f in findings],
        "recommended_actions": recommended_actions,
        "proposed_actions": [_proposed_action_to_dict(a) for a in proposed_actions],
        "alert": (
            {
                "dedupe_key": grouped_incident.dedupe_key,
                "title": grouped_incident.title,
                "impact_summary": grouped_incident.impact_summary,
                "child_incidents": [
                    {
                        "finding_type": c.finding_type,
                        "summary": c.summary,
                        "peer": c.peer,
                        "severity": c.severity,
                    }
                    for c in grouped_incident.child_incidents
                ],
                "consolidated_logs": grouped_incident.consolidated_logs,
            }
            if grouped_incident
            else None
        ),
    }
def _normalize_snapshot(raw_snapshot: dict[str, Any]) -> BgpSnapshot:
    """
    Normalize a raw snapshot into the internal BGP snapshot model.
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
    Normalize route records from Adj RIB In, Loc RIB, and Adj RIB Out.
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
            findings.append(
                BgpFinding(
                    finding_type="session_down",
                    severity="critical",
                    summary=f"BGP session to {peer} is not established",
                    peer=peer,
                    confidence=0.92,
                    occurred_at=neighbor.last_event_at,
                    evidence={
                        "session_state": session_state,
                        "shared_dependency": shared_dependency,
                        "last_error": last_error,
                        "address_family": neighbor.address_family,
                        "root_cause_hint": str(
                            shared_dependency or "peering_or_reachability_issue"
                        ),
                    },
                    logs=_select_logs(logs, peer, session_state, last_error, shared_dependency),
                )
            )
            continue

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
                    summary=f"Prefix {prefix} reached Adj RIB In but did not enter Loc RIB",
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
                    summary=f"Prefix {prefix} exists in Loc RIB but is absent from Adj RIB Out",
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
    grouped_incident: BgpGroupedIncident | None,
) -> list[dict[str, Any]]:
    """
    Build safe read only recommendations.

    These remain operator guidance only.
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


def _build_proposed_actions(
    *,
    fabric: str,
    device: str,
    findings: list[BgpFinding],
    grouped_incident: BgpGroupedIncident | None,
) -> list[BgpProposedAction]:
    """
    Build proposed actions for Option B foundations.

    Important:
    These are proposals only.
    No action is executed in this phase.
    """
    proposed: list[BgpProposedAction] = []
    seen_ids: set[str] = set()

    for finding in findings:
        if finding.finding_type == "session_down":
            proposed.append(
                BgpProposedAction(
                    action_id=f"validate_session:{finding.peer}",
                    title="Validate BGP session inputs",
                    summary=(
                        f"Validate reachability and peering inputs for {finding.peer} before "
                        f"considering any intrusive recovery step"
                    ),
                    action_type="read_only_validation",
                    target={
                        "fabric": fabric,
                        "device": device,
                        "peer": finding.peer,
                    },
                    rationale=(
                        "The session is not established. Read only checks should happen before "
                        "any reset or policy change."
                    ),
                    evidence=finding.evidence,
                    risk_level="low",
                    approval_required=False,
                    prerequisites=[
                        "Confirm underlay reachability to the peer",
                        "Confirm ASN, update source, and transport settings",
                        "Inspect the last known error and related logs",
                    ],
                    commands=[],
                    rollback_hint=None,
                )
            )

            proposed.append(
                BgpProposedAction(
                    action_id=f"propose_session_reset:{finding.peer}",
                    title="Propose controlled BGP session reset",
                    summary=(
                        f"Potentially reset the session to {finding.peer} only after validating "
                        f"reachability and configuration state"
                    ),
                    action_type="gated_remediation",
                    target={
                        "fabric": fabric,
                        "device": device,
                        "peer": finding.peer,
                    },
                    rationale=(
                        "A session reset is disruptive and should only be considered after the "
                        "operator confirms that it is appropriate."
                    ),
                    evidence=finding.evidence,
                    risk_level="medium",
                    approval_required=True,
                    approval_reason="Session reset may withdraw routes and change traffic flow",
                    blocked=True,
                    blocked_reason="Execution is not enabled in Check in 4",
                    prerequisites=[
                        "Validate underlay reachability",
                        "Validate remote ASN and update source",
                        "Confirm that the failure is not due to a wider shared dependency",
                    ],
                    commands=[
                        "clear bgp neighbor <peer> soft or hard reset depending on platform policy"
                    ],
                    rollback_hint=(
                        "If the reset worsens impact, stop further resets and investigate "
                        "the shared dependency"
                    ),
                )
            )

        elif finding.finding_type == "inbound_policy_drop":
            proposed.append(
                BgpProposedAction(
                    action_id=f"validate_inbound_policy:{finding.prefix}",
                    title="Validate inbound policy handling",
                    summary=(
                        f"Inspect inbound policy, route acceptance rules, and validation handling "
                        f"for {finding.prefix}"
                    ),
                    action_type="read_only_validation",
                    target={
                        "fabric": fabric,
                        "device": device,
                        "prefix": finding.prefix,
                        "peer": finding.peer,
                    },
                    rationale=(
                        "The route appears in Adj RIB In but not in Loc RIB, which strongly points "
                        "to inbound policy or validation handling."
                    ),
                    evidence=finding.evidence,
                    risk_level="low",
                    approval_required=False,
                    prerequisites=[
                        "Inspect inbound policy references",
                        "Inspect route validation state",
                        "Compare accepted and denied route counters if available",
                    ],
                    commands=[],
                    rollback_hint=None,
                )
            )

            proposed.append(
                BgpProposedAction(
                    action_id=f"propose_inbound_policy_change:{finding.prefix}",
                    title="Propose inbound policy adjustment",
                    summary=(
                        f"Potentially adjust inbound policy logic affecting {finding.prefix} after "
                        f"review and approval"
                    ),
                    action_type="gated_policy_change",
                    target={
                        "fabric": fabric,
                        "device": device,
                        "prefix": finding.prefix,
                        "peer": finding.peer,
                    },
                    rationale=(
                        "Changing route policy can alter accepted routes and blast radius beyond the "
                        "single prefix if done incorrectly."
                    ),
                    evidence=finding.evidence,
                    risk_level="high",
                    approval_required=True,
                    approval_reason="Policy changes may alter route acceptance across multiple prefixes",
                    blocked=True,
                    blocked_reason="Execution is not enabled in Check in 4",
                    prerequisites=[
                        "Review current policy and route match conditions",
                        "Review expected import behavior",
                        "Prepare explicit rollback policy or revert plan",
                    ],
                    commands=[
                        "apply reviewed inbound route policy update through approved change path"
                    ],
                    rollback_hint="Rollback to the previous inbound policy revision",
                )
            )

        elif finding.finding_type == "outbound_policy_drop":
            proposed.append(
                BgpProposedAction(
                    action_id=f"validate_outbound_policy:{finding.prefix}",
                    title="Validate outbound policy handling",
                    summary=(
                        f"Inspect outbound policy and advertisement eligibility for {finding.prefix}"
                    ),
                    action_type="read_only_validation",
                    target={
                        "fabric": fabric,
                        "device": device,
                        "prefix": finding.prefix,
                        "peer": finding.peer,
                    },
                    rationale=(
                        "The route appears in Loc RIB but not in Adj RIB Out, which strongly points "
                        "to outbound policy or advertisement gating."
                    ),
                    evidence=finding.evidence,
                    risk_level="low",
                    approval_required=False,
                    prerequisites=[
                        "Inspect export policy and peer specific filters",
                        "Inspect route advertisement counters if available",
                        "Confirm that route eligibility conditions are met",
                    ],
                    commands=[],
                    rollback_hint=None,
                )
            )

        elif finding.finding_type == "peer_not_advertising":
            proposed.append(
                BgpProposedAction(
                    action_id=f"validate_sender_advertisement:{finding.peer}",
                    title="Validate sender side advertisement state",
                    summary=(
                        f"Inspect sender side Adj RIB Out and route generation state for {finding.peer}"
                    ),
                    action_type="read_only_validation",
                    target={
                        "fabric": fabric,
                        "device": device,
                        "peer": finding.peer,
                    },
                    rationale=(
                        "The session is up but no routes were received. That often means the sender "
                        "is not advertising or an upstream dependency is preventing route generation."
                    ),
                    evidence=finding.evidence,
                    risk_level="low",
                    approval_required=False,
                    prerequisites=[
                        "Inspect sender side export state",
                        "Confirm route generation on the sender",
                        "Inspect shared dependency such as route reflector or policy domain",
                    ],
                    commands=[],
                    rollback_hint=None,
                )
            )

        elif finding.finding_type == "session_unstable":
            proposed.append(
                BgpProposedAction(
                    action_id=f"validate_instability:{finding.peer}",
                    title="Validate session instability cause",
                    summary=(
                        f"Inspect transport instability, timer expiry patterns, and shared dependency "
                        f"signals for {finding.peer}"
                    ),
                    action_type="read_only_validation",
                    target={
                        "fabric": fabric,
                        "device": device,
                        "peer": finding.peer,
                    },
                    rationale=(
                        "Instability often reflects a deeper dependency issue. The safe path is to "
                        "confirm the root issue before considering recovery actions."
                    ),
                    evidence=finding.evidence,
                    risk_level="low",
                    approval_required=False,
                    prerequisites=[
                        "Inspect recent logs around timer expiry or flap events",
                        "Inspect dependency level failures",
                        "Inspect whether multiple peers share the same instability pattern",
                    ],
                    commands=[],
                    rollback_hint=None,
                )
            )

        elif finding.finding_type == "best_path_issue":
            proposed.append(
                BgpProposedAction(
                    action_id=f"validate_best_path:{finding.prefix}",
                    title="Validate best path selection inputs",
                    summary=(
                        f"Inspect best path inputs and route attribute selection for {finding.prefix}"
                    ),
                    action_type="read_only_validation",
                    target={
                        "fabric": fabric,
                        "device": device,
                        "prefix": finding.prefix,
                    },
                    rationale=(
                        "No best path is selected even though the prefix is in Loc RIB. The safe step "
                        "is to validate attributes and selection evidence."
                    ),
                    evidence=finding.evidence,
                    risk_level="low",
                    approval_required=False,
                    prerequisites=[
                        "Inspect path attribute comparison inputs",
                        "Inspect next hop reachability",
                        "Inspect route eligibility and multipath state",
                    ],
                    commands=[],
                    rollback_hint=None,
                )
            )

    if grouped_incident is not None:
        proposed.append(
            BgpProposedAction(
                action_id=f"grouped_incident_review:{grouped_incident.root_cause}",
                title="Review grouped incident before approving any remediation",
                summary=(
                    "Treat the correlated incident as the parent problem and avoid approving "
                    "repeated child actions until the shared dependency is understood"
                ),
                action_type="coordination_guidance",
                target={
                    "fabric": fabric,
                    "device": device,
                    "root_cause": grouped_incident.root_cause,
                },
                rationale=(
                    "When several symptoms share one dependency, approval should focus on the "
                    "shared issue rather than many repetitive child remediations."
                ),
                evidence={
                    "dedupe_key": grouped_incident.dedupe_key,
                    "child_count": len(grouped_incident.child_incidents),
                },
                risk_level="low",
                approval_required=False,
                prerequisites=[
                    "Review the parent incident evidence bundle",
                    "Confirm the shared dependency",
                    "Avoid duplicate approvals for equivalent child actions",
                ],
                commands=[],
                rollback_hint=None,
            )
        )

    unique: list[BgpProposedAction] = []
    for action in proposed:
        if action.action_id in seen_ids:
            continue
        seen_ids.add(action.action_id)
        unique.append(action)

    return unique


def _build_approval_summary(proposed_actions: list[BgpProposedAction]) -> dict[str, Any]:
    """
    Summarize approval needs across the proposed actions.
    """
    approval_required_count = sum(1 for action in proposed_actions if action.approval_required)
    blocked_count = sum(1 for action in proposed_actions if action.blocked)

    return {
        "has_proposed_actions": bool(proposed_actions),
        "approval_required_count": approval_required_count,
        "blocked_count": blocked_count,
        "execution_enabled": False,
    }


def _build_summary(
    findings: list[BgpFinding],
    grouped_incident: BgpGroupedIncident | None,
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


def _sort_findings(findings: list[BgpFinding]) -> list[BgpFinding]:
    """
    Sort findings in a deterministic order.
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


def _proposed_action_to_dict(action: BgpProposedAction) -> dict[str, Any]:
    return {
        "action_id": action.action_id,
        "title": action.title,
        "summary": action.summary,
        "action_type": action.action_type,
        "target": action.target,
        "rationale": action.rationale,
        "evidence": action.evidence,
        "risk_level": action.risk_level,
        "approval_required": action.approval_required,
        "approval_reason": action.approval_reason,
        "blocked": action.blocked,
        "blocked_reason": action.blocked_reason,
        "prerequisites": action.prerequisites,
        "commands": action.commands,
        "rollback_hint": action.rollback_hint,
    }


def _index_routes(routes: list[BgpRouteRecord]) -> dict[str, list[BgpRouteRecord]]:
    indexed: dict[str, list[BgpRouteRecord]] = {}
    for route in routes:
        if not route.prefix:
            continue
        indexed.setdefault(route.prefix, []).append(route)
    return indexed


def _select_logs(logs: list[BgpLogRecord], *terms: Any) -> list[str]:
    """
    Select relevant log lines for a finding.
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
