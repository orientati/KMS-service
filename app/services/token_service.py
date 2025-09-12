from __future__ import annotations

from app.schemas.token import TokenResponse, TokenCreate


def verify_token(token: str) -> TokenResponse:
    pass


def create_token(data: TokenCreate) -> str:
    pass
