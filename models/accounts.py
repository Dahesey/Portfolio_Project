from pydantic import BaseModel
from datetime import datetime


class AccountOffering(BaseModel):
    id: str
    member_id: str
    amount: int
    timestamp: datetime

class AccountTithe(BaseModel):
    id: str
    member_id: str
    amount: int
    timestamp: datetime


class AccountWelfare(BaseModel):
    id: str
    member_id: str
    amount:int
    timestamp: datetime


class AccountSeed(BaseModel):
    id: str
    member_id: str
    amount: int
    timestamp: datetime