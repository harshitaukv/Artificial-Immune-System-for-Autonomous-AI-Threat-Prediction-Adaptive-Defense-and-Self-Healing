"""Shared fixtures.

A single small immune system is trained once per session and reused, so the
suite exercises the *real* models rather than mocks while still running in
well under a minute.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parent.parent / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from astrasec.data.generator import DatasetGenerator            # noqa: E402
from astrasec.engines.behavior import BehaviorLearningEngine    # noqa: E402
from astrasec.engines.defense import AdaptiveDefenseEngine      # noqa: E402
from astrasec.engines.health import HealthRiskAnalyzer          # noqa: E402
from astrasec.engines.memory import ImmuneMemoryEngine          # noqa: E402
from astrasec.engines.prediction import ThreatPredictionEngine  # noqa: E402
from astrasec.pipeline import ImmuneSystem                      # noqa: E402
from astrasec.schemas import AppContext, InspectRequest         # noqa: E402


@pytest.fixture(scope="session")
def corpus():
    gen = DatasetGenerator(seed=11)
    return gen.generate(4_000)


@pytest.fixture(scope="session")
def trained_system(corpus):
    """A fully trained, in-process immune system (models only, no disk I/O)."""
    behavior = BehaviorLearningEngine()
    behavior.fit(corpus[corpus.label == "benign"].text.tolist(), verbose=False)

    prediction = ThreatPredictionEngine()
    prediction.fit(corpus.text.tolist(), corpus.label.tolist(), verbose=False)

    memory = ImmuneMemoryEngine()
    memory.seed_holdout(corpus[corpus.label == "benign"].text.tolist()[:800])

    return ImmuneSystem(
        behavior=behavior,
        prediction=prediction,
        health=HealthRiskAnalyzer(),
        defense=AdaptiveDefenseEngine(),
        memory=memory,
    )


@pytest.fixture
def fresh_system(trained_system):
    """The trained system with all runtime state cleared between tests."""
    trained_system.reset()
    trained_system.memory.cells.clear()
    trained_system.memory._dirty = True
    trained_system.memory.total_encounters = 0
    trained_system.memory.recall_hits = 0
    trained_system.memory.promoted_rules.clear()
    trained_system.memory.candidate_rules.clear()
    trained_system.defense.active_rules.clear()
    trained_system.defense._compiled.clear()
    return trained_system


@pytest.fixture
def app_ctx():
    return AppContext(app_id="test-app", app_name="Test Assistant")


@pytest.fixture
def hardened_app():
    return AppContext(
        app_id="hardened", app_name="Hardened Assistant",
        system_prompt_protected=True, output_filtering_enabled=True,
        pii_redaction_enabled=True, authentication_required=True,
        rate_limiting_enabled=True, sandbox_enabled=True, logging_enabled=True,
        tool_calling_enabled=False, retrieval_enabled=False,
        dependencies=["fastapi", "transformers"], last_security_review_days=5,
    )


@pytest.fixture
def weak_app():
    return AppContext(
        app_id="weak", app_name="Unhardened Assistant",
        system_prompt_protected=False, output_filtering_enabled=False,
        pii_redaction_enabled=False, authentication_required=False,
        rate_limiting_enabled=False, sandbox_enabled=False, logging_enabled=False,
        tool_calling_enabled=True, retrieval_enabled=True,
        dependencies=["langchain", "pyyaml"],
        known_vulnerable_dependencies=["langchain<0.1.0", "pyyaml<5.4"],
        last_security_review_days=300,
    )


def make_request(prompt: str, **kw) -> InspectRequest:
    return InspectRequest(prompt=prompt, **kw)
