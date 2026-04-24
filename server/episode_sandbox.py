"""Episode sandbox — wall-clock + step-limit guard with state-integrity rollback."""

from __future__ import annotations

import hashlib
import json
import time
from copy import deepcopy


def _snapshot_hash(value) -> str:
    """Deterministic SHA-256 hash of an arbitrary value.

    Uses json.dumps with sort_keys=True and default=str so that dict-type
    protected fields (task_def, live_requirements) are compared by content
    rather than by object identity, preventing false-positive rollbacks.
    """
    serialized = json.dumps(value, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode()).hexdigest()


EPISODE_TIMEOUT_SECONDS = 300
MAX_STEPS_PER_EPISODE = 20
PROTECTED_STATE_FIELDS = [
    "_task_def",
    "_live_requirements",
    "_threat_graph",
    "_step_count",
    "_network",
    "_host_index",
]


class EpisodeTimeout(Exception):
    pass


class StateIntegrityViolation(Exception):
    pass


class EpisodeSandbox:
    def __init__(self, env):
        self.env = env
        self._start_time = None
        self._protected_snapshot: dict = {}   # field -> deepcopy for rollback
        self._snapshot_hashes: dict = {}      # field -> SHA-256 of snapshot
        self._hacking_attempts: list[str] = []

    def __enter__(self):
        self._start_time = time.time()
        self._protected_snapshot = {}
        self._snapshot_hashes = {}
        for field in PROTECTED_STATE_FIELDS:
            if hasattr(self.env, field):
                original = deepcopy(getattr(self.env, field))
                self._protected_snapshot[field] = original
                self._snapshot_hashes[field] = _snapshot_hash(original)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None and exc_type is not EpisodeTimeout:
            return False

        elapsed = time.time() - self._start_time
        if elapsed > EPISODE_TIMEOUT_SECONDS:
            raise EpisodeTimeout(
                f"Episode exceeded {EPISODE_TIMEOUT_SECONDS}s wall-clock limit"
            )

        # Compare by content hash to avoid false-positives from identity comparison
        for field, original_value in self._protected_snapshot.items():
            current_value = getattr(self.env, field, None)
            current_hash = _snapshot_hash(current_value)
            if current_hash != self._snapshot_hashes[field]:
                setattr(self.env, field, original_value)
                self._hacking_attempts.append(
                    f"Protected field '{field}' was mutated externally"
                )
        return False

    def check_step_limit(self, step_count: int) -> None:
        """Raise EpisodeTimeout if step_count >= MAX_STEPS_PER_EPISODE."""
        if step_count >= MAX_STEPS_PER_EPISODE:
            raise EpisodeTimeout(
                f"Episode exceeded {MAX_STEPS_PER_EPISODE} step limit"
            )

    def elapsed_seconds(self) -> float:
        if self._start_time is None:
            return 0.0
        return time.time() - self._start_time

    def was_hacked(self) -> bool:
        return len(self._hacking_attempts) > 0

    def hacking_report(self) -> list[str]:
        return self._hacking_attempts.copy()
