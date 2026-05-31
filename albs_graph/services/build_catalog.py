"""A cached catalog of known ALBS build numbers (D120).

ALBS build ids are *sparse* -- most numbers have no build -- so guessing one
(57809, 17811, ...) hits a 404. This persists a small on-disk db of real build
ids, both the most recent ones fetched from the ``/api/v1/builds/`` list and any
the user has actually analyzed, so the workbench can offer valid ids to pick and
autocomplete instead of guessing.

The store is the persistence layer; the live fetch + parse live in
``adapters.albs`` (``fetch_build_list`` / ``BuildSummary``). Reads degrade to an
empty catalog on any error -- a missing or corrupt file is never fatal.
"""

from __future__ import annotations

import json
from pathlib import Path

from albs_graph.adapters._http_cache import default_cache_root
from albs_graph.adapters.albs import BuildSummary


class BuildCatalog:
    """A JSON-backed, upsert-by-build-id catalog of :class:`BuildSummary` rows."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (default_cache_root() / "build-catalog.json")

    def load(self) -> list[BuildSummary]:
        """All known builds, newest build first; empty on a missing/corrupt file.

        Sorted by build time (``created_at``) descending, falling back to the
        build id (which tracks time) when a recorded build carries no timestamp.
        """

        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        builds = [BuildSummary.from_dict(item) for item in raw if isinstance(item, dict)]
        return sorted(builds, key=lambda build: (build.created_at or "", build.build_id), reverse=True)

    def build_ids(self) -> list[int]:
        return [build.build_id for build in self.load()]

    def save(self, builds: list[BuildSummary]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = [build.to_dict() for build in builds]
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def merge(self, new_builds: list[BuildSummary]) -> list[BuildSummary]:
        """Upsert ``new_builds`` (newest wins on id collision); return the catalog."""

        by_id = {build.build_id: build for build in self.load()}
        for build in new_builds:
            by_id[build.build_id] = build
        merged = sorted(by_id.values(), key=lambda build: build.build_id, reverse=True)
        self.save(merged)
        return merged

    def record(self, build: BuildSummary) -> list[BuildSummary]:
        """Upsert a single build (e.g. one the user just analyzed)."""

        return self.merge([build])
