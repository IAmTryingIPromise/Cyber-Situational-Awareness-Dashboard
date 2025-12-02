from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class AssetBase(BaseModel):
    name: str
    type: str
    vendor: str
    model: str
    department: str
    os_family: str
    version: str
    description: Optional[str] = None
    h_cpe: str
    risk_level: Optional[float] = None

class AssetCreate(AssetBase):
    pass

class AssetUpdate(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    department: Optional[str] = None
    os_family: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None
    h_cpe: Optional[str] = None
    risk_level: Optional[float] = None

class Asset(AssetBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    model_config = {
        "from_attributes": True
    }