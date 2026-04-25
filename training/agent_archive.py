"""Historical archive utilities for FSP/PFSP training."""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class ArchivedAgent:
    role: str
    version: str
    checkpoint_path: str
    iteration: int
    metadata: Dict[str, float]


class AgentArchive:
    """Stores historical checkpoints and win-rate metadata in a JSON index."""

    def __init__(self, index_path: str = "training/archive/index.json"):
        self.index_path = Path(index_path)
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        self._items: List[ArchivedAgent] = self._load()

    def _load(self) -> List[ArchivedAgent]:
        if not self.index_path.exists():
            return []
        raw = json.loads(self.index_path.read_text(encoding="utf-8"))
        return [ArchivedAgent(**item) for item in raw]

    def save(self) -> None:
        payload = [asdict(item) for item in self._items]
        self.index_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def add(
        self,
        role: str,
        version: str,
        checkpoint_path: str,
        iteration: int,
        metadata: Optional[Dict[str, float]] = None,
    ) -> None:
        self._items.append(
            ArchivedAgent(
                role=role,
                version=version,
                checkpoint_path=checkpoint_path,
                iteration=iteration,
                metadata=metadata or {},
            )
        )
        self.save()

    def list_role(self, role: str) -> List[ArchivedAgent]:
        return [item for item in self._items if item.role == role]

    def latest(self, role: str) -> Optional[ArchivedAgent]:
        role_items = self.list_role(role)
        if not role_items:
            return None
        return max(role_items, key=lambda x: x.iteration)

    def sample_fsp(self, role: str) -> Optional[ArchivedAgent]:
        items = self.list_role(role)
        if not items:
            return None
        return random.choice(items)

    def sample_pfsp(self, role: str, temperature: float = 1.0) -> Optional[ArchivedAgent]:
        """Prioritize opponents where blue has lower win-rate."""
        items = self.list_role(role)
        if not items:
            return None

        weights: List[float] = []
        for item in items:
            blue_win_rate = float(item.metadata.get("blue_win_rate", 0.5))
            difficulty = max(0.0, min(1.0, 1.0 - blue_win_rate))
            weights.append(max(1e-6, difficulty**temperature))

        return random.choices(items, weights=weights, k=1)[0]

    def must_beat_all(self, threshold: float = 0.55) -> bool:
        """Return True when every archived red has blue_win_rate >= threshold."""
        red_items = self.list_role("red")
        if not red_items:
            return True
        return all(float(item.metadata.get("blue_win_rate", 0.0)) >= threshold for item in red_items)
