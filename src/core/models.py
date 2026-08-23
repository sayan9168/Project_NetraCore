from pydantic import BaseModel, Field
from typing import Literal, List, Optional
from datetime import datetime
import uuid

class LegalAuthority(BaseModel):
    class Config:
        extra = "forbid"
        
    warrant_id: str
    issued_by: str
    expires_at: datetime
    scope: dict

class CaseIntakeRequest(BaseModel):
    class Config:
        extra = "forbid"
        
    case_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    legal_authority: LegalAuthority
    target_type: Literal["android", "cloud", "media", "network"]
    evidence_uri: str
    priority: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"

class Finding(BaseModel):
    class Config:
        extra = "forbid"
        
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    module: Literal["MODULE_A", "MODULE_B", "MODULE_C", "MODULE_D"]
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    title: str
    description: str
    confidence: float = Field(ge=0.0, le=1.0)
    raw_data: dict = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
