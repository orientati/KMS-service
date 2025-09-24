from __future__ import annotations

from pydantic import BaseModel


class TokenResponse(BaseModel):
    verified: bool
    expired: bool
    expires_in: int
    expires_at: int
    username: str
    user_id: int
    session_id: int


class TokenCreate(BaseModel):
    user_id: int
    username: str
    session_id: int
    expires_in: int  # in minuti

class TokenVerifyRequest(BaseModel):
    token: str