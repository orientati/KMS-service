from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from app.schemas.token import TokenCreate, TokenResponse, TokenVerifyRequest, TokenCreateResponse
from app.services.http_client import OrientatiException
from app.services.token_service import create_token, verify_token

router = APIRouter()


@router.post("/create", response_model=TokenCreateResponse)
async def api_create_token(payload: TokenCreate) -> TokenCreateResponse:
    try:
        token_str = await create_token(payload)
        return TokenCreateResponse(token=token_str)
    except OrientatiException as e:
        return JSONResponse(
            status_code=e.status_code,
            content={
                "message": e.message,
                "details": e.details,
                "url": e.url
            }
        )
@router.post("/verify", response_model=TokenResponse)
async def api_verify_token(payload: TokenVerifyRequest) -> TokenResponse:
    try:
        # Service returns a dict, FastAPI/Pydantic validates it against TokenResponse
        result = await verify_token(payload.token)
        return result
    except OrientatiException as e:
        return JSONResponse(
            status_code=e.status_code,
            content={
                "message": e.message,
                "details": e.details,
                "url": e.url
            }
        )