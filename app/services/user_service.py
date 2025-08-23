from __future__ import annotations

import json
from typing import Iterable
from sqlalchemy.orm import Session
from sqlalchemy import select
from app.models.user import User
from app.schemas.user import UserCreate, UserUpdate


def list_users(db: Session, limit: int = 50, offset: int = 0) -> Iterable[User]:
    stmt = select(User).limit(limit).offset(offset)
    return db.execute(stmt).scalars().all()


def get_user(db: Session, user_id: int) -> User | None:
    return db.get(User, user_id)


def create_user(db: Session, payload: UserCreate) -> User:
    user = User(**payload.model_dump())
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def update_user(db: Session, user_id: int, payload: UserUpdate) -> User | None:
    user = db.get(User, user_id)
    if not user:
        return None
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(user, field, value)
    db.commit()
    db.refresh(user)
    return user


def upsert_user_from_event(db: Session, event_body: str) -> None:
    """
    Esempio di handler per evento broker.
    Atteso un JSON tipo:
      {"type":"user_created","user":{"id":123,"username":"x","email":"y","full_name":"..."}}
    oppure:
      {"type":"user_updated","user":{"id":123,...}}
    """
    data = json.loads(event_body)
    user_data = data.get("user") or {}
    if "id" not in user_data:
        return

    user = db.get(User, user_data["id"])
    if user is None:
        # create with explicit id to allinearsi al servizio autoritativo
        user = User(
            id=user_data["id"],
            username=user_data.get("username", ""),
            email=user_data.get("email", ""),
            full_name=user_data.get("full_name"),
        )
        db.add(user)
    else:
        user.username = user_data.get("username", user.username)
        user.email = user_data.get("email", user.email)
        user.full_name = user_data.get("full_name", user.full_name)

    db.commit()
