#from __future__ import annotations
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.schemas.token import TokenCreate, TokenResponse, TokenVerifyRequest, TokenCreateResponse
from app.services.http_client import OrientatiException
from app.services.token_service import create_token, verify_token

router = APIRouter()


@router.post("/create", response_model=TokenCreateResponse)
def api_create_token(payload: TokenCreate) -> TokenCreateResponse:
    try:
        token_str = create_token(payload)
        return TokenCreateResponse(token=token_str)
    except OrientatiException as e:
        raise HTTPException(status_code=e.status_code,
                            detail={"message": e.message, "details": e.details, "url": e.url})
@router.post("/verify", response_model=TokenResponse)
def api_verify_token(payload: TokenVerifyRequest) -> TokenResponse:
    try:
        return verify_token(payload.token)
    except OrientatiException as e:
        raise HTTPException(status_code=e.status_code,
                            detail={"message": e.message, "details": e.details, "url": e.url})