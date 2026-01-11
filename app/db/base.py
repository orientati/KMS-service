from app.db.base_class import Base


def import_models():
    from app.models.key_pair import KeyPair  # noqa: E402 F401
