from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from agent_framework import Executor, Workflow, WorkflowBuilder, WorkflowContext, handler

from app.agents.diff_agent import DiffAgentExecutor
from app.agents.fix_suggestion_agent import FixSuggestionAgentExecutor
from app.agents.reviewer_manager import ReviewerManagerExecutor
from app.agents.security_agent import SecurityAgentExecutor
from app.agents.style_agent import StyleAgentExecutor
from app.agents.test_coverage_agent import TestCoverageAgentExecutor
from app.orchestration.shared_state import ReviewState


class CoordinatorDispatcher(Executor):
    """Stores ReviewState into Microsoft Agent Framework shared state and fans out to 4 parallel analysis agents."""

    def __init__(
        self,
        emit_event: Callable[[str, str, dict[str, Any]], Awaitable[None]],
    ) -> None:
        super().__init__(id="coordinator_dispatcher")
        self._emit = emit_event

    @handler
    async def dispatch(
        self, state: ReviewState, ctx: WorkflowContext[ReviewState]
    ) -> None:
        ctx.set_state("review_state", state)
        await self._emit(
            state.review_id,
            "fan_out_started",
            {
                "agents": [
                    "diff_agent",
                    "style_agent",
                    "security_agent",
                    "test_coverage_agent",
                ],
                "repository": state.repository_name,
                "base_commit": state.base_commit,
                "target_commit": state.target_commit,
            },
        )
        await ctx.send_message(state)


def build_review_workflow(
    emit_event: Callable[[str, str, dict[str, Any]], Awaitable[None]],
) -> Workflow:
    """
    Construct the 6-agent Microsoft Agent Framework Fan-Out / Fan-In workflow:
      CoordinatorDispatcher
        ├──> DiffAgentExecutor
        ├──> StyleAgentExecutor
        ├──> SecurityAgentExecutor
        └──> TestCoverageAgentExecutor
               └──(fan-in)──> ReviewerManagerExecutor ──> FixSuggestionAgentExecutor
    """
    dispatcher = CoordinatorDispatcher(emit_event)
    diff_exec = DiffAgentExecutor(emit_event)
    style_exec = StyleAgentExecutor(emit_event)
    security_exec = SecurityAgentExecutor(emit_event)
    test_cov_exec = TestCoverageAgentExecutor(emit_event)
    reviewer_manager = ReviewerManagerExecutor(emit_event)
    fix_suggestion = FixSuggestionAgentExecutor(emit_event)

    return (
        WorkflowBuilder(
            name="Swarm-MultiAgent-Review",
            description="Six-agent Fan-out / Fan-in automated code review workflow",
            start_executor=dispatcher,
        )
        .add_fan_out_edges(
            dispatcher,
            [diff_exec, style_exec, security_exec, test_cov_exec],
        )
        .add_fan_in_edges(
            [diff_exec, style_exec, security_exec, test_cov_exec],
            reviewer_manager,
        )
        .add_edge(reviewer_manager, fix_suggestion)
        .build()
    )
