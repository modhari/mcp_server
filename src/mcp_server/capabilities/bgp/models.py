from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class BgpNeighborRecord:
    """
    Normalized neighbor state used by the analyzer.

    The incoming payload can be vendor neutral but still incomplete. The analyzer keeps
    the model permissive so Lattice can provide as much or as little detail as it has
    gathered from YANG and gRPC reads.
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
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BgpRouteRecord:
    """
    Normalized route visibility record.

    A single route may appear in one or more BGP tables. Keeping the record flat makes it
    easier for the analyzer to answer a deterministic question: where in the BGP pipeline
    did this route disappear.
    """

    prefix: str
    peer: str | None = None
    next_hop: str | None = None
    reason: str | None = None
    best: bool = False
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
    evidence: dict[str, Any] = field(default_factory=dict)
    logs: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class BgpGroupedIncident:
    """
    Correlated incident used to reduce alert fatigue.

    The grouped incident is the parent object that collapses many related raw symptoms
    into one alertable event with a single dedupe key.
    """

    dedupe_key: str
    title: str
    root_cause: str
    impact_summary: str
    grouped_events: list[dict[str, Any]] = field(default_factory=list)
    consolidated_logs: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
