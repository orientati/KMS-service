from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


def import_models():
    from app.models.key_pair import KeyPair  # noqa: E402 F401
