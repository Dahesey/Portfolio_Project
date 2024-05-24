from pydantic import BaseModel
from datetime import datetime

class LoginSchema(BaseModel):
    id: int
    email: str
    password:str
    timestamp: datetime

class RegistrationSchema(BaseModel):
    id: int
    fullname: str
    email: str
    ghana_card: str
    date_of_birth: str
    password: str
    confirm: str
    timestamp: datetime