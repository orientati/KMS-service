#from __future__ import annotations
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.schemas.token import TokenCreate, TokenResponse, TokenVerifyRequest, TokenCreateResponse
from app.services.token_service import create_token, verify_token

router = APIRouter()


@router.post("/create", response_model=TokenCreateResponse)
def api_create_token(payload: TokenCreate) -> TokenCreateResponse:
    token_str = create_token(payload)
    return TokenCreateResponse(token=token_str)

@router.post("/verify", response_model=TokenResponse)
def api_verify_token(payload: TokenVerifyRequest) -> TokenResponse:
    try:
        return verify_token(payload.token)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )