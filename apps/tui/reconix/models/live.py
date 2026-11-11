"""Where an assessment's run stands on the Core API (store/live.py drives it).

The API holds the real run: the plan, every action, its approval and tool runs, and the
findings. This is only what the app needs to ask it for the next thing and to show what
came back: ids, counts and what is in flight. Nothing here is made up.
"""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class LiveRun:
    assessment_id: str = ""  # the API's assessment (its scope was approved there)
    agent_run_id: str = ""  # the drafted plan's run, until it is sent
    model_name: str = ""  # the model the API planned with
    plan_text: str = ""  # what the agent said about its plan (masked by the API)
    plan_steps: List[dict] = field(default_factory=list)  # the API's PlanStep rows
    blocked_steps: List[dict] = field(default_factory=list)  # steps the agent's check refused
    sent: bool = False  # the plan's first step went to the API (Run plan)
    steps_done: int = 0  # actions the API has given the run so far
    waiting_approval: str = ""  # the API approval the run waits for ("" for none)
    agent_done: bool = False  # the agent has no next step
    analyzed: bool = False  # the API's analysis came back
    analysis_summary: str = ""
    busy: bool = False  # a call to the API is in flight
    failed: str = ""  # why the last call failed ("" when it didn't)
    finding_ids: Dict[str, str] = field(default_factory=dict)  # app fid -> API finding_id
    actions: List[str] = field(default_factory=list)  # the API's action ids, in order
    finished_tools: List[str] = field(default_factory=list)  # tools whose runs completed
    to_analyze: List[str] = field(default_factory=list)  # API finding ids awaiting analysis
    code_scan_id: str = ""  # a source scope's code scan (agent run) on the API
    code_scan_done: bool = False  # its findings were read (the code scan has no plan or steps)
