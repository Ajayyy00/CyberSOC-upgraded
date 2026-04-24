"""Tests for Task 5 — Episode Sandbox."""

import os
import sys

import pytest

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from server.episode_sandbox import (
    EpisodeSandbox,
    EpisodeTimeout,
    MAX_STEPS_PER_EPISODE,
)


class _MockEnv:
    def __init__(self):
        self._task_def = {"difficulty": "easy", "attack_chain": []}
        self._live_requirements = {"must_kill": []}
        self._threat_graph = None
        self._step_count = 0


def test_sandbox_enters_and_exits_cleanly():
    env = _MockEnv()
    with EpisodeSandbox(env):
        pass


def test_elapsed_seconds_positive():
    env = _MockEnv()
    with EpisodeSandbox(env) as sb:
        # Even fast: elapsed should be >= 0 immediately, > 0 after a tick.
        # Force a small wait-free tick by reading time twice.
        e1 = sb.elapsed_seconds()
        # Busy-loop a small amount to guarantee elapsed > 0
        end = e1 + 1e-3
        while sb.elapsed_seconds() <= end:
            pass
        assert sb.elapsed_seconds() > 0.0


def test_step_limit_raises_at_max():
    env = _MockEnv()
    sb = EpisodeSandbox(env)
    with pytest.raises(EpisodeTimeout):
        sb.check_step_limit(MAX_STEPS_PER_EPISODE)


def test_step_limit_ok_below_max():
    env = _MockEnv()
    sb = EpisodeSandbox(env)
    sb.check_step_limit(MAX_STEPS_PER_EPISODE - 1)


def test_state_integrity_violation_detected():
    env = _MockEnv()
    with EpisodeSandbox(env) as sb:
        env._step_count = 9999  # mutate protected field
    assert sb.was_hacked() is True


def test_state_rollback_on_violation():
    env = _MockEnv()
    original = dict(env._task_def)
    with EpisodeSandbox(env):
        env._task_def["difficulty"] = "hacked"
    assert env._task_def == original


def test_no_false_hacking_on_clean_run():
    env = _MockEnv()
    with EpisodeSandbox(env) as sb:
        pass
    assert sb.was_hacked() is False


def test_hacking_report_lists_violated_fields():
    env = _MockEnv()
    with EpisodeSandbox(env) as sb:
        env._step_count = 42
    report = sb.hacking_report()
    assert any("_step_count" in r for r in report)
