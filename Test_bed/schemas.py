from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field


# Supported tool names
ToolName = Literal["send_email", "add_calendar_event"]


# Agent 1: Extraction
class ActionItem(BaseModel):
    action: str
    source: str


class Extraction(BaseModel):
    summary: str
    action_items: List[ActionItem]
    sender_email: Optional[str] = None


# Agent 2: Execution plan
class PlanStep(BaseModel):
    tool: ToolName
    args: Dict[str, Any]
    reason: str


class ExecutionPlan(BaseModel):
    steps: List[PlanStep]


# Agent 3: Structured tool-call proposal
class ToolCall(BaseModel):
    tool: Optional[ToolName] = None
    args: Dict[str, Any] = Field(default_factory=dict)


# Tool execution result
class ToolResult(BaseModel):
    status: str
    tool: Optional[str] = None
    result: Optional[Dict[str, Any]] = None


# Experiment stage record
class StageRecord(BaseModel):
    stage: str
    agent: Optional[str] = None
    data: Any


# Experiment run metadata
class RunMetadata(BaseModel):
    run_id: str
    scenario_id: str
    attack_type: str
    defense: str

    agent1_model: str
    agent2_model: str
    agent3_model: str

    template_id: Optional[str] = None
    payload_id: Optional[str] = None
    variant: Optional[str] = None
    trial_id: Optional[str] = None
    injection_position: Optional[str] = None
    agent_model_configuration: Optional[Dict[str, str]] = None
    agent3_mode: Optional[Literal["strict", "neutral"]] = None
    defense_enabled: Optional[bool] = None
    defense_status: Optional[str] = None
    defense_version: Optional[str] = None
    defense_configuration: Optional[Dict[str, Any]] = None
    temperature: Optional[float] = None
    random_seed: Optional[int] = None
    executor_mode: Optional[Literal["dry_run"]] = None
    technical_failure: bool = False
    failed_agent: Optional[str] = None

    attacker_model: Optional[str] = None
    attacker_goal: Optional[str] = None


# Complete experiment result
class RunResult(BaseModel):
    metadata: RunMetadata
    stages: List[StageRecord]
    metrics: Dict[str, Any]