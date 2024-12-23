from pydantic import BaseModel
from typing import Dict, Optional
from datetime import datetime


# Decoys


# Deployment
class CyberpotDeployments(BaseModel):
    public_id: Optional[str] = None
    name: str
    container_id: str
    decoy: str
    port: str
    last_started: Optional[datetime] = None
    resource_usages: Dict[str, str]
    action_status: str

# Resources
class CyberpotResourceAllocation(BaseModel):
    cpu_limit: int
    memory_limit: float
    swap_limit: float
    virtual_disk_limit: int

class CyberpotResourceSaver(BaseModel):
    resource_saver: int
