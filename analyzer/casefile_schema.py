from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


Confidence = Literal["high", "medium", "low", "n/a"]
LayerType = Literal["observed", "derived", "heuristic", "unknown"]
SourceType = Literal["pcap_frame", "pcap_metric", "driver_log", "ap_log", "system"]


class CasefileIncidentWindow(BaseModel):
    start_ts: float
    end_ts: float
    trigger_frame: Optional[int] = None
    trigger_reason: str


class CasefileSummary(BaseModel):
    title: str
    confidence: Confidence
    next_checks: List[str]


class CasefileEvidenceItem(BaseModel):
    layer: LayerType
    message: str
    source_type: SourceType
    source_ref: str
    timestamp: Optional[float] = None
    confidence: Confidence
    explainability: str
    missing_reason: Optional[str] = None
    counter_evidence_refs: List[str] = Field(default_factory=list)


class CasefileLayers(BaseModel):
    observed: List[CasefileEvidenceItem]
    derived: List[CasefileEvidenceItem]
    heuristic: List[CasefileEvidenceItem]
    unknown: List[CasefileEvidenceItem]


class CasefilePingData(BaseModel):
    full_list: List[Dict[str, Any]]
    pairs: List[Dict[str, Any]]
    losses: List[Dict[str, Any]]
    stats: Dict[str, Any]


class CasefileV1(BaseModel):
    schema_version: str = "1.0"
    generator_version: str = "casefile-v1"
    analysis_id: str
    incident_id: str
    incident_window: CasefileIncidentWindow
    summary: CasefileSummary
    layers: CasefileLayers
    ping: CasefilePingData
