"""Tests for Task 1 — Fix Crash Bug + Project Scaffold."""

import os
import sys

# Ensure project root (MetaRound2) is on sys.path before importing server.*
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from server.play_environment import CyberSOCEnvironment


def test_reset_does_not_crash():
    env = CyberSOCEnvironment()
    obs = env.reset(task_id="easy")
    assert obs is not None


def test_live_requirements_populated():
    env = CyberSOCEnvironment()
    env.reset(task_id="easy")
    assert env._live_requirements is not None
    assert isinstance(env._live_requirements, dict)


def test_adaptive_flag_default():
    env = CyberSOCEnvironment()
    assert env._adaptive is False


def test_adaptive_flag_set():
    env = CyberSOCEnvironment(adaptive=True)
    assert env._adaptive is True
