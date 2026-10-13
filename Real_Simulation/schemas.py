from typing import List, Optional, Dict, Any
from pydantic import BaseModel


class ActionItem(BaseModel):
    action: str
    source: str


class Extraction(BaseModel):
    summary: str
    action_items: List[ActionItem]


class PlanStep(BaseModel):
    tool: str
    args: Dict[str, Any]
    reason: str


class ExecutionPlan(BaseModel):
    steps: List[PlanStep]


class ToolCall(BaseModel):
    tool: Optional[str] = None
    args: Dict[str, Any] = {}


class ToolResult(BaseModel):
    status: str
    tool: Optional[str] = None
    result: Optional[Dict[str, Any]] = None


class StageRecord(BaseModel):
    stage: str
    agent: Optional[str] = None
    data: Any


class RunMetadata(BaseModel):
    run_id: str
    scenario_id: str
    attack_type: str
    defense: str
    agent1_model: str
    agent2_model: str
    agent3_model: str


class RunResult(BaseModel):
    metadata: RunMetadata
    stages: List[StageRecord]
    metrics: Dict[str, Any]