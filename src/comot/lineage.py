"""Lineage graph: every derived copy points back to its parents."""
from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

from .errors import UnknownObject

ARTIFACT_TYPES: tuple[str, ...] = (
    "recording",
    "transcript",
    "clip",
    "features",
    "dataset_version",
    "model_version",
)

# Artifact statuses. "tainted" means a model still in use that was trained on
# withdrawn data; it stays usable only until the retrained model ships.
STATUSES: tuple[str, ...] = ("active", "tainted", "deleted", "retired")

INTERNAL = "internal"


@dataclass
class Artifact:
    artifact_id: str
    type: str
    content_hash: str | None
    storage_uri: str | None
    holder: str  # "internal" or a licence id
    sharded: bool
    participant_id: str | None  # set on recordings only
    project_id: str | None  # set on recordings only
    created_by: str
    created_at: str
    status: str = "active"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class LineageEdge:
    parent_id: str
    child_id: str
    purpose: str
    created_by: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LineageGraph:
    artifacts: dict[str, Artifact] = field(default_factory=dict)
    edges: list[LineageEdge] = field(default_factory=list)
    _out: dict[str, list[LineageEdge]] = field(default_factory=dict)
    _in: dict[str, list[LineageEdge]] = field(default_factory=dict)

    def get(self, artifact_id: str) -> Artifact:
        try:
            return self.artifacts[artifact_id]
        except KeyError:
            raise UnknownObject(f"unknown artifact {artifact_id!r}") from None

    def add(self, artifact: Artifact, edges: Iterable[LineageEdge] = ()) -> None:
        # Parents must already exist, so the graph can never contain a cycle.
        edges = list(edges)
        for e in edges:
            self.get(e.parent_id)
        self.artifacts[artifact.artifact_id] = artifact
        for e in edges:
            self.edges.append(e)
            self._out.setdefault(e.parent_id, []).append(e)
            self._in.setdefault(e.child_id, []).append(e)

    def parents(self, artifact_id: str) -> list[str]:
        return [e.parent_id for e in self._in.get(artifact_id, [])]

    def children_edges(self, artifact_id: str) -> list[LineageEdge]:
        return list(self._out.get(artifact_id, []))

    def ancestors(self, artifact_id: str, include_self: bool = False) -> list[str]:
        """All artifacts this one derives from, nearest first."""
        self.get(artifact_id)
        seen: set[str] = set()
        order: list[str] = []
        queue = deque([artifact_id])
        while queue:
            node = queue.popleft()
            for p in self.parents(node):
                if p not in seen:
                    seen.add(p)
                    order.append(p)
                    queue.append(p)
        return ([artifact_id] if include_self else []) + order

    def descendants(self, artifact_id: str) -> list[str]:
        self.get(artifact_id)
        seen: set[str] = set()
        order: list[str] = []
        queue = deque([artifact_id])
        while queue:
            node = queue.popleft()
            for e in self._out.get(node, []):
                if e.child_id not in seen:
                    seen.add(e.child_id)
                    order.append(e.child_id)
                    queue.append(e.child_id)
        return order

    def source_recordings(self, artifact_id: str) -> list[str]:
        """The raw recordings an artifact ultimately comes from."""
        return [
            a for a in self.ancestors(artifact_id, include_self=True) if self.artifacts[a].type == "recording"
        ]

    def affected_by(self, recording_ids: Iterable[str], revoked: set[str] | None) -> list[str]:
        """Artifacts that a withdrawal reaches, recordings included.

        ``revoked`` is the set of withdrawn uses, or None for a full withdrawal
        (everything derived from the recordings, and the recordings themselves).

        For a partial withdrawal an artifact is reached when some edge on its
        path from a recording was made for a revoked use. Everything downstream
        of a reached artifact is reached too, because it derives from it.
        """
        recording_ids = list(recording_ids)
        reached: list[str] = []
        seen: set[str] = set()

        def mark(a: str) -> None:
            if a not in seen:
                seen.add(a)
                reached.append(a)

        if revoked is None:
            for r in recording_ids:
                mark(r)
                for d in self.descendants(r):
                    mark(d)
            return reached

        queue: deque[tuple[str, bool]] = deque((r, False) for r in recording_ids)
        visited: set[tuple[str, bool]] = set()
        while queue:
            node, tainted = queue.popleft()
            if (node, tainted) in visited:
                continue
            visited.add((node, tainted))
            for e in self._out.get(node, []):
                child_tainted = tainted or e.purpose in revoked
                if child_tainted:
                    mark(e.child_id)
                queue.append((e.child_id, child_tainted))
        return reached
