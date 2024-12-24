from pydantic import BaseModel
from typing import Optional

class ModelCredentials(BaseModel):
    public_id: Optional[str]
    username: str
    password: str