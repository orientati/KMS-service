from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime
from app.db.base_class import Base

class KeyPair(Base):
    __tablename__ = "key_pairs"

    id = Column(Integer, primary_key=True, index=True)
    kid = Column(String(255), unique=True, index=True, nullable=False)  # Key ID (es. timestamp)
    private_key = Column(Text, nullable=False)
    public_key = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
