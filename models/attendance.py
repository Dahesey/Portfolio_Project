from pydantic import BaseModel
from datetime import datetime


class Attendance(BaseModel):
    id: int
    fullname: str
    contact: int
    location: str
    timestamp: datetime


