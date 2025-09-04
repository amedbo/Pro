from pydantic import BaseModel
from datetime import datetime
from typing import List, Optional
from .models import IndicatorType

# Indicator Schemas
class IndicatorBase(BaseModel):
    indicator_type: IndicatorType
    value: str

class IndicatorCreate(IndicatorBase):
    pass

class Indicator(IndicatorBase):
    id: int
    threat_id: int
    created_at: datetime

    class Config:
        from_attributes = True

# Threat Schemas
class ThreatBase(BaseModel):
    name: str
    description: Optional[str] = None
    threat_class: Optional[str] = None # Make it optional

class ThreatCreate(ThreatBase):
    pass

class Threat(ThreatBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    indicators: List[Indicator] = []

    class Config:
        from_attributes = True
