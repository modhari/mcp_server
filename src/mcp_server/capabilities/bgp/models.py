from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class BgpNeighborRecord:
    """
    Normalized neighbor state used by the analyzer.

    Notes:
    This model is intentionally vendor neutral so Lattice can fill it from structured
    Netconfig and YANG gRPC reads rather than CLI parsing.

    shared_dependency is important for alert grouping. For example:
    - a route reflector id
    - an uplink bundle
    - a spine device
    - a policy domain
    """

    peer: str
    session_state: str = "unknown"
    prefixes_received: int | None = None
    prefixes_accepted: int | None = None
    prefixes_advertised: int | None = None
    best_path_count: int | None = None
    shared_dependency: str | None = None
    last_error: str | None = None
    last_event_at: str | None = None
    address_family: str = "ipv4_unicast"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BgpRouteRecord:
    """
    Normalized route visibility record.

    A route record represents one route observation at one stage in the BGP pipeline.
    The same prefix may appear several times with different peers or path state.
    """

    prefix: str
    peer: str | None = None
    next_hop: str | None = None
    reason: str | None = None
    best: bool = False
    shared_dependency: str | None = None
    address_family: str = "ipv4_unicast"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BgpEventRecord:
    """
    Normalized event record used for symptom correlation.

    occurred_at should be an ISO like string when available.
    The analyzer keeps it as a string so we do not force timestamp formatting at the
    Lattice edge for Check in 2.
    """

    event_type: str
    peer: str | None = None
    prefix: str | None = None
    shared_dependency: str | None = None
    severity: str = "warning"
    occurred_at: str | None = None
    message: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BgpLogRecord:
    """
    Normalized log record.

    This gives us one consistent log structure for consolidated incident output.
    """

    message: str
    occurred_at: str | None = None
    source: str | None = None
    peer: str | None = None
    prefix: str | None = None
    shared_dependency: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BgpSnapshot:
    """
    Top level normalized BGP snapshot.

    This is the contract Check in 2 wants Lattice to move toward.
    correlation_window_seconds is used by the grouping logic to decide whether multiple
    raw symptoms belong to one parent incident.
    """

    correlation_window_seconds: int = 180
    neighbors: list[BgpNeighborRecord] = field(default_factory=list)
    loc_rib: list[BgpRouteRecord] = field(default_factory=list)
    adj_rib_in: list[BgpRouteRecord] = field(default_factory=list)
    adj_rib_out: list[BgpRouteRecord] = field(default_factory=list)
    events: list[BgpEventRecord] = field(default_factory=list)
    logs: list[BgpLogRecord] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BgpFinding:
    """
    Structured diagnostic finding returned by the analyzer.
    """

    finding_type: str
    severity: str
    summary: str
    peer: str | None = None
    prefix: str | None = None
    confidence: float = 0.5
    occurred_at: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    logs: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class BgpChildIncident:
    """
    A child symptom that rolls into a parent grouped incident.

    The main alert should be raised on the parent incident only. Child incidents are
    retained for drill down and evidence, which directly helps with alert fatigue.
    """

    finding_type: str
    summary: str
    peer: str | None = None
    prefix: str | None = None
    severity: str = "warning"
    confidence: float = 0.5
    occurred_at: str | None = None


@dataclass(frozen=True)
class BgpGroupedIncident:
    """
    Correlated incident used to reduce alert fatigue.

    dedupe_key must stay stable for the same root issue so downstream alerting does not
    produce noisy duplicate pages.
    """

    dedupe_key: str
    title: str
    root_cause: str
    impact_summary: str
    correlation_window_seconds: int
    child_incidents: list[BgpChildIncident] = field(default_factory=list)
    grouped_events: list[dict[str, Any]] = field(default_factory=list)
    consolidated_logs: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
