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
from app.cache.review_cache import ReviewCache
from app.intelligence.structure_indexer import build_structure_index
from app.orchestration.shared_state import ReviewState
from app.planning.review_planner import build_review_plan


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
        cache_dir = state.cache_dir or (state.workspace_dir.parent / "_cache")
        cache = ReviewCache(cache_dir)
        commit_context = f"{state.base_commit}..{state.target_commit}"

        state.structure_index = build_structure_index(
            state.workspace_dir,
            state.changed_files,
            cache=cache,
            commit_context=commit_context,
        )
        state.review_plan = build_review_plan(
            changed_files=state.changed_files,
            structure_index=state.structure_index,
            policy=state.policy,
            diff_text=state.diff_text,
        )
        state.cache_stats = cache.stats.to_dict()

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
                "risk_tier": state.review_plan.get("risk_tier", "medium"),
                "files_indexed": state.structure_index.get("files_indexed", 0),
                "symbols_indexed": state.structure_index.get("symbols_indexed", 0),
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
